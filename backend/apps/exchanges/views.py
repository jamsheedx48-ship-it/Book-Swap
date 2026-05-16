from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework import status
from apps.utils.n8n import send_email_via_n8n
from .models import Exchange,MeetupDetail
from .serializers import ExchangeCreateSerializer, ExchangeSerializer,MeetupSerializer
from apps.notifications.sqs import send_notification
from ..chat.models import Conversation
from apps.notifications.utils import send_realtime_notification

#List exchanges
class ExchangeListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        exchanges = Exchange.objects.filter(requester=user) | Exchange.objects.filter(receiver=user)
        serializer = ExchangeSerializer(exchanges, many=True)
        return Response(serializer.data)

#Create exchange request
class ExchangeRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ExchangeCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        exchange = serializer.save()

        # Notify the book owner that someone requested an exchange
        send_notification(
            notification_type="REQUEST_RECEIVED",
            fcm_token=exchange.receiver.fcm_token,
            payload={
                "requester_name": exchange.requester.name,
                "book_title": exchange.requested_book.title,
                "exchange_id": str(exchange.id),
            }
        )

        # when user requests a swap
        try:
            send_realtime_notification(
                recipient=exchange.receiver,
                notification_type='swap_requested',
                message=f'{exchange.requester.name} wants to swap "{exchange.requested_book.title}" with you.'
            )
        except Exception as e:
            print(f"REALTIME NOTIF ERROR: {e}")

        return Response(ExchangeSerializer(exchange).data, status=status.HTTP_201_CREATED)

# Accept / reject / complete exchange
class ExchangeActionView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Exchange.objects.get(pk=pk)
        except Exchange.DoesNotExist:
            raise ValidationError("Exchange not found.")

    def post(self, request, pk, action):
        exchange = self.get_object(pk)
        user = request.user

        if action == "accept":
            if exchange.receiver != user:
                raise PermissionDenied("Only the receiver can accept.")
            if exchange.status != Exchange.Status.PENDING:
                raise ValidationError("Only pending exchanges can be accepted.")
            exchange.status = Exchange.Status.ACCEPTED

            conversation = Conversation.objects.create()
            conversation.participants.add(exchange.requester, exchange.receiver)
            exchange.conversation = conversation


            send_notification(
                notification_type="REQUEST_ACCEPTED",
                fcm_token=exchange.requester.fcm_token,
                payload={
                    "book_title":exchange.requested_book.title,
                    "exchange_id": str(exchange.id),
                }
            )

            send_realtime_notification(
                recipient=exchange.requester,
                notification_type='swap_accepted',
                message=f'{exchange.receiver.name} accepted your swap request for "{exchange.requested_book.title}"!'
            )

            send_email_via_n8n(
                to_email=exchange.requester.email,
                subject="Your swap request was accepted!",
                html=f"""
                    <h2>Great news!</h2>
                    <p><strong>{exchange.receiver.name}</strong> accepted your swap request for
                    <strong>{exchange.requested_book.title}</strong>.</p>
                    <p>Log in to Book Swap to proceed with the exchange.</p>
                """
            )

        elif action == "reject":
            if exchange.receiver != user:
                raise PermissionDenied("Only the receiver can reject.")
            if exchange.status != Exchange.Status.PENDING:
                raise ValidationError("Only pending exchanges can be rejected.")
            exchange.status = Exchange.Status.REJECTED

            #Notify the requester that their request was rejected
            send_notification(
                notification_type="REQUEST_REJECTED",
                fcm_token=exchange.requester.fcm_token,
                payload={
                    "book_title": exchange.requested_book.title,
                    "exchange_id": str(exchange.id),
                }
            )

            send_realtime_notification(
                recipient=exchange.requester,
                notification_type='swap_rejected',
                message=f'{exchange.receiver.name} declined your swap request for "{exchange.requested_book.title}".'
            )

            send_email_via_n8n(
                to_email=exchange.requester.email,
                subject="Your swap request was declined",
                html=f"""
                    <h2>Swap Request Declined</h2>
                    <p>Unfortunately, <strong>{exchange.receiver.name}</strong> declined your swap request for
                    <strong>{exchange.requested_book.title}</strong>.</p>
                    <p>Don't worry — there are more books available on Book Swap!</p>
                """
    )

        elif action == "complete":
            if user not in (exchange.requester, exchange.receiver):
                raise PermissionDenied("You are not part of this exchange.")
            if exchange.status != Exchange.Status.ACCEPTED:
                raise ValidationError("Only accepted exchanges can be completed.")
            exchange.status = Exchange.Status.COMPLETED

            send_email_via_n8n(
                to_email=exchange.requester.email,
                subject="Swap completed!",
                html=f"""
                     <h2>Swap Completed 🎉</h2>
                     <p>Your exchange of <strong>{exchange.offered_book.title}</strong> for
                     <strong>{exchange.requested_book.title}</strong> is now complete.</p>
                     <p>Thanks for using Book Swap!</p>
                """
            )
            send_email_via_n8n(
                to_email=exchange.receiver.email,
                subject="Swap completed!",
                html=f"""
                     <h2>Swap Completed 🎉</h2>
                     <p>Your exchange of <strong>{exchange.requested_book.title}</strong> for
                     <strong>{exchange.offered_book.title}</strong> is now complete.</p>
                     <p>Thanks for using Book Swap!</p>
                """
            )
        
        elif action == "cancel":
            if exchange.requester!=user:
                raise PermissionDenied("Only the requester can cancel.")
            if exchange.status!= Exchange.Status.PENDING:
                raise ValidationError("Only pending exchanges can be cancelled.")
            exchange.status = Exchange.Status.CANCELLED

        else:
            raise ValidationError("Invalid action. Use accept, reject, or complete.")

        exchange.save()
        return Response(ExchangeSerializer(exchange).data)
    
#check the book laredy have a pendin req
class CheckPendingExchangeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, book_id):
        exists = Exchange.objects.filter(
            requester=request.user,
            requested_book_id=book_id,
            status=Exchange.Status.PENDING,
        ).exists()
        return Response({"has_pending": exists})    
    
# view meetup details and create meetup details
class MeetupView(APIView):
    permission_classes = [IsAuthenticated]

    def get_exchange(self, pk, user):
        try:
            exchange = Exchange.objects.get(pk=pk)
        except Exchange.DoesNotExist:
            raise ValidationError("Exchange not found.")
        if user not in (exchange.requester, exchange.receiver):
            raise PermissionDenied("You are not part of this exchange.")
        if exchange.status != Exchange.Status.ACCEPTED:
            raise ValidationError("Exchange must be accepted before setting a meetup.")
        return exchange

    def get(self, request, pk):
        exchange = self.get_exchange(pk, request.user)
        try:
            serializer = MeetupSerializer(exchange.meetup)
            return Response(serializer.data)
        except MeetupDetail.DoesNotExist:
            return Response({"detail": "No meetup proposed yet."}, status=404)

    def post(self, request, pk):
        exchange = self.get_exchange(pk, request.user)
        # Prevent duplicate meetup creation
        if hasattr(exchange, 'meetup'):
            raise ValidationError("Meetup already proposed. Use confirm endpoint.")
        serializer = MeetupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(exchange=exchange, proposed_by=request.user)
        return Response(serializer.data, status=201)

# meetup confirmation
class MeetupConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            exchange = Exchange.objects.get(pk=pk)
        except Exchange.DoesNotExist:
            raise ValidationError("Exchange not found.")
        if request.user not in (exchange.requester, exchange.receiver):
            raise PermissionDenied("You are not part of this exchange.")
        try:
            meetup = exchange.meetup
        except MeetupDetail.DoesNotExist:
            raise ValidationError("No meetup proposed yet.")
        if meetup.proposed_by == request.user:
            raise PermissionDenied("You can't confirm your own meetup proposal.")
        if meetup.confirmed:
            raise ValidationError("Meetup already confirmed.")
        meetup.confirmed = True
        meetup.save()
        return Response(MeetupSerializer(meetup).data)