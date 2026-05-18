import os
import httpx
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
import json

DJANGO_BASE = os.getenv("DJANGO_INTERNAL_URL", "http://backend:8000")
INTERNAL_SECRET = os.getenv("AGENT_INTERNAL_SECRET", "")
HEADERS = {"X-Internal-Secret": INTERNAL_SECRET}


def django_get(path: str, params: dict) -> dict:
    with httpx.Client() as client:
        r = client.get(f"{DJANGO_BASE}{path}", params=params, headers=HEADERS)
        r.raise_for_status()
        return r.json()


def django_post(path: str, data: dict) -> dict:
    with httpx.Client() as client:
        r = client.post(f"{DJANGO_BASE}{path}", json=data, headers=HEADERS)
        r.raise_for_status()
        return r.json()


@tool
def get_user_books(user_id: int) -> str:
    """Get all books owned by the user."""
    result = django_get("/api/agent/books/", {"user_id": user_id})
    return json.dumps(result)


@tool
def find_who_wants_my_books(user_id: int) -> str:
    """Find users who have pending exchange requests for books owned by this user."""
    result = django_get("/api/agent/wanted/", {"user_id": user_id})
    return json.dumps(result)


@tool
def find_book_owners(book_id: int) -> str:
    """Find who owns a specific book by book ID."""
    result = django_get("/api/agent/owners/", {"book_id": book_id})
    return json.dumps(result)


@tool
def create_exchange(
    requester_id: int,
    receiver_id: int,
    offered_book_id: int,
    requested_book_id: int,
    message: str = "Matched by BookSwap AI Agent",
) -> str:
    """Create a swap exchange between two users."""
    result = django_post("/api/agent/exchange/", {
        "requester_id": requester_id,
        "receiver_id": receiver_id,
        "offered_book_id": offered_book_id,
        "requested_book_id": requested_book_id,
        "message": message,
    })
    return json.dumps(result)


TOOLS = [get_user_books, find_who_wants_my_books, find_book_owners, create_exchange]

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=os.getenv("GROQ_API_KEY"),
).bind_tools(TOOLS)

TOOL_MAP = {t.name: t for t in TOOLS}


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]


def agent_node(state: AgentState):
    response = llm.invoke(state["messages"])
    return {"messages": [response]}


def tool_node(state: AgentState):
    last = state["messages"][-1]
    results = []
    for call in last.tool_calls:
        tool_fn = TOOL_MAP[call["name"]]
        output = tool_fn.invoke(call["args"])
        results.append(ToolMessage(content=output, tool_call_id=call["id"]))
    return {"messages": results}


def should_continue(state: AgentState):
    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "tools"
    return END


graph = StateGraph(AgentState)
graph.add_node("agent", agent_node)
graph.add_node("tools", tool_node)
graph.set_entry_point("agent")
graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
graph.add_edge("tools", "agent")

swap_agent = graph.compile()


async def run_swap_agent(user_id: int, user_message: str, history: list = []) -> str:
    from langchain_core.messages import AIMessage

    system_prompt = f"""You are BookSwap AI, a smart book swap matchmaking agent.
The current user's ID is {user_id}.

Your job:
1. Get the user's books using get_user_books — note the exact book IDs returned
2. Find who wants their books using find_who_wants_my_books — note exact IDs
3. Cross-reference to find the best swap match
4. Suggest the best match clearly: "Swap your [Book A] with [Name] for [Book B]"
5. If the user confirms, create the exchange using create_exchange

CRITICAL RULES:
- NEVER guess or invent IDs. Always use the exact numeric IDs returned by tools.
- offered_book_id must be from the user's own books (from get_user_books)
- requested_book_id must be from the other person's offered book (from find_who_wants_my_books)
- receiver_id must be the requester's user ID from find_who_wants_my_books
- requester_id is always {user_id}

Be concise and friendly."""

    messages = [HumanMessage(content=system_prompt)]

    for msg in history:
        if msg.role == "user":
            messages.append(HumanMessage(content=msg.content))
        elif msg.role == "assistant":
            messages.append(AIMessage(content=msg.content))

    messages.append(HumanMessage(content=user_message))

    result = await swap_agent.ainvoke({"messages": messages})
    last = result["messages"][-1]
    return last.content