from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.text import slugify

class Event(models.Model):
    STATUS_CHOICES = (
        ('draft', 'Szkic'),
        ('publish', 'Opublikowano')
    )
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=250,
                            unique_for_date='planning_date', default=None)
    description = models.TextField(verbose_name='opis wydarzenia', blank=True, max_length=1000)
    created = models.DateTimeField(auto_now_add=True)
    planning_date = models.DateTimeField(blank=True, null=True)
    publish = models.DateTimeField(default=timezone.now)
    organizer = models.ForeignKey(User, on_delete=models.CASCADE)
    want_to_listen = models.ManyToManyField(User, related_name='want_to_listen', default=None, blank=True, null=True)
    status = models.CharField(max_length=15,
                              choices=STATUS_CHOICES,
                              default='publish')
    duration = models.IntegerField(blank=True, null=True)
    icon = models.FileField(upload_to='icons/', default='icons/default.png', null=True)
    attachment = models.FileField(upload_to='attachments/', blank=True, null=True)
    link = models.CharField(max_length=1000, blank=True, null=True)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.title)
        super(Event, self).save(*args, **kwargs)

    class Meta:
        ordering = ('planning_date',)

    def __str__(self):
        return self.title


class Comment(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    content = models.TextField(max_length=1000)
    if_edited = models.BooleanField(default=False)
    if_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ('-created',)


class MFAUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, unique=True)
    code = models.IntegerField(max_length=6)

