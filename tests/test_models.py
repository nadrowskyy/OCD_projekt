import datetime
from django.test import TestCase, Client
from schedule.models import Event, Comment
from django.contrib.auth.models import User


class TestModels(TestCase):

    def setUp(self):
        self.user1 = User.objects.create(
            username='Username',
            first_name='Jhon',
            last_name='Doe',
            email='example@com',
            password='Password'
        )
        self.event1 = Event.objects.create(
            title='Title 1',
            description='Description',
            created=datetime.datetime.now(),
            planning_date=datetime.datetime.now(),
            publish=datetime.datetime.now(),
            organizer=self.user1
        )

    def test_event_slug(self):

        self.assertEquals(self.event1.slug, 'title-1')
