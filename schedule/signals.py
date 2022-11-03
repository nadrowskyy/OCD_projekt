from django.dispatch import receiver
from django.db.models.signals import post_migrate
from django.contrib.auth.models import User, Group
from django.contrib.auth import get_user_model


@receiver(post_migrate)
def populate_models(sender, **kwargs):
    group, created = Group.objects.get_or_create(name='admin')
    group.save()
    group, created = Group.objects.get_or_create(name='employee')
    group.save()

    User = get_user_model()
    if not User.objects.filter(username='superuser').exists():
        User.objects.create_superuser(username='superuser',
                                      email='super@email.com',
                                      password='super')
        suser = User.objects.get(username='superuser')
        admin = Group.objects.get(name='admin')
        suser.groups.add(admin)
