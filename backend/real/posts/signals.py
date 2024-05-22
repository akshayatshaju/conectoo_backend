from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Notification
from asgiref.sync import async_to_sync
import channels.layers
import json

@receiver(post_save, sender=Notification)
def send_notification(sender, instance, created, **kwargs):
    print(instance,instance.from_user.username)
    print("signaling.....from......notfication")
    if created:
        channel_layer = channels.layers.get_channel_layer()
        print(channel_layer,"channel_layerr")
        group_name = f"notify_{instance.to_user_id}"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "send_notification",
                "value": json.dumps({
                    "notification_type": instance.notification_type,
                    "from_user_id": instance.from_user_id,
                    "from_user":instance.from_user.username,
                    "created": instance.created.isoformat(),
                    "is_seen": instance.is_seen
                })
            }
        )
