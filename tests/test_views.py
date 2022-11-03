import datetime
from django.test import TestCase, Client
from django.urls import reverse
from schedule.models import Event, Comment
from django.contrib.auth.models import User
from schedule.forms import CreateUserForm
from django.contrib.auth.models import Group


class TestViews(TestCase):

    def setUp (self):
        self.client = Client()
        self.home_page_url = reverse('home')
        self.login_page_url = reverse('login')
        self.events_list_url = reverse('events_list')
        self.register_page_url = reverse('register')
        self.create_event_url = reverse('create_event')
        self.about_url = reverse('about')
        self.users_list_url = reverse('users_list')
        self.user_details_url = reverse('user_details', args=[1])
        self.user_edit_url = reverse('user_edit', args=[1])
        # poniżej zakładamy, że istnieje event o indeksie 1 ale nie zawsze będzie to prawdą
        # dlatego należy utworzyć obiekt Event o takim indeksie do testów
        self.event_edit_url = reverse('event_edit', args=['1'])
        self.event_details_url = reverse('event_details', args=[1])
        self.my_profile_url = reverse('my_profile')
        self.user1 = User.objects.create(
            username='Username',
            first_name='Jhon',
            last_name='Doe',
            email='example@com',
            password='Password'
        )

        self.event1 = Event.objects.create(
            title='Title',
            slug='Slug',
            description='Description',
            created=datetime.datetime.now(),
            planning_date=datetime.datetime.now(),
            publish=datetime.datetime.now(),
            organizer=self.user1
        )

    def test_home_page_GET (self):
        response = self.client.get(self.home_page_url)

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'schedule/home.html')

    def test_login_page_GET (self):
        # nie wiem
        pass

    def test_login_POST (self):
        response = self.client.post(self.login_page_url, {
            'username': 'superuser',
            'password': 'super'
        })

        self.assertEquals(response.status_code, 302)
        # uzywamy kodu 302 wiec nie ma response
        # self.assertTemplateUsed(response)

    def test_login_POST_next (self):
        response = self.client.post(self.login_page_url, {
            'username': 'superuser',
            'password': 'super',
            'next': 'home'
        })

        self.assertEquals(response.status_code, 302)

    def test_register_page_GET (self):
        response = self.client.get(self.register_page_url)

        self.assertEquals(response.status_code, 200)

    def test_register_page_POST (self):
        response = self.client.post(self.register_page_url, {
            'username': self.user1.username,
            'password': self.user1.password,
            'first_name': 'sample',
            'last_name': 'sample',
            'email': 'sample',
            'password1': 'sample',
            'password2': 'sample',
        })
        CreateUserForm(data={
            'username': 'sample',
            'first_name': 'sample',
            'last_name': 'sample',
            'email': 'sample',
            'password1': 'sample',
            'password2': 'sample',
        })

        # self.assertTrue(form.is_valid())
        self.assertEquals(response.status_code, 302)

    def test_events_list_GET (self):
        response = self.client.get(self.events_list_url)

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'schedule/events_list.html')

    def test_create_event_GET (self):
        response = self.client.get(self.create_event_url)
        self.assertEquals(response.status_code, 302)

    def test_create_event_POST (self):
        response = self.client.post(self.create_event_url, {
            'organizer': self.user1,
            'planning_date': datetime.datetime.now()
        })
        self.assertEquals(response.status_code, 302)
        # self.assertTemplateUsed(response, 'schedule/create_event.html')

    def test_logout_user_GET (self):
        response = self.client.get(self.home_page_url)
        self.assertEquals(response.status_code, 200)

    def test_about_GET (self):
        response = self.client.get(self.about_url)
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'schedule/about.html')

    def test_users_list_GET (self):
        response = self.client.get(self.users_list_url)
        self.assertEquals(response.status_code, 302)
        # self.assertTemplateUsed(response, 'schedule/users_list.html')

    def test_user_details_GET (self):
        response = self.client.get(self.user_details_url)
        self.assertEquals(response.status_code, 302)
        # self.assertTemplateUsed(response, 'schedule/user_edit.html')

    def test_event_edit_GET (self):
        response = self.client.get(self.event_edit_url)
        self.assertEquals(response.status_code, 302)

    def test_event_delete_GET (self):
        pass

    def test_my_profile_POST_change_profile (self):
        group = Group.objects.get(name='employee')
        self.user1.groups.add(group)
        response = self.client.post(self.my_profile_url, {
            'user': self.user1,
            'organizer': self.user1,
            'change_profile': '1'
        })

        self.assertEquals(response.status_code, 302)

    def test_event_detail_GET (self):
        response = self.client.get(self.event_details_url)

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'schedule/event_details.html')

    def test_event_detail_POST_new_comment (self):
        Comment.objects.create(
            author=self.user1,
            event=self.event1,
            created=datetime.datetime.now(),
            content='Comment'
        )

        response = self.client.post(self.event_details_url, data={
            'delete': 'Nones'
        })
