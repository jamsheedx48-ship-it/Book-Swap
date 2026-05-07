from rest_framework import serializers
from .models import Exchange


class ExchangeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exchange
        fields = ["offered_book", "requested_book", "message"]

    def validate(self, attrs):
        requester = self.context["request"].user
        offered_book = attrs["offered_book"]
        requested_book = attrs["requested_book"]

        # Requester must own the offered book
        if offered_book.user != requester:
            raise serializers.ValidationError("You don't own the offered book.")

        # Can't request your own book
        if requested_book.user == requester:
            raise serializers.ValidationError("You can't request your own book.")

        # No duplicate pending exchange
        if Exchange.objects.filter(
            requester=requester,
            requested_book=requested_book,
            status=Exchange.Status.PENDING,
        ).exists():
            raise serializers.ValidationError(
                "You already have a pending exchange for this book."
            )

        return attrs

    def create(self, validated_data):
        requester = self.context["request"].user
        requested_book = validated_data["requested_book"]
        return Exchange.objects.create(
            requester=requester,
            receiver=requested_book.user,
            **validated_data,
        )


class ExchangeSerializer(serializers.ModelSerializer):
    requester = serializers.StringRelatedField()
    receiver = serializers.StringRelatedField()
    offered_book = serializers.StringRelatedField()
    requested_book = serializers.StringRelatedField()
    requester_id = serializers.IntegerField(source="requester.id", read_only=True)
    receiver_id = serializers.IntegerField(source="receiver.id", read_only=True)

    class Meta:
        model = Exchange
        fields = [
            "id",
            "requester",
            "requester_id",
            "receiver",
            "receiver_id",
            "offered_book",
            "requested_book",
            "status",
            "message",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields