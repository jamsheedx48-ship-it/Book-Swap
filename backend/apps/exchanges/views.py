from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework import status
from apps.utils.n8n import send_email_via_n8n
from .models import Exchange
from .serializers import ExchangeCreateSerializer, ExchangeSerializer
from apps.notifications.sqs import send_notification


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

            send_notification(
                notification_type="REQUEST_ACCEPTED",
                fcm_token=exchange.requester.fcm_token,
                payload={
                    "book_title":exchange.requested_book.title,
                    "exchange_id": str(exchange.id),
                }
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
    
