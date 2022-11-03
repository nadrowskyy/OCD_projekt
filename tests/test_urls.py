from django.test import SimpleTestCase
from django.urls import reverse, resolve
from schedule.views import home_page, events_list, register_page, login_page, logout_user, create_event, about, password_reset_request, \
    users_list, my_profile, handler_403, user_details, user_edit, delete_user, event_edit, delete_event, event_details

class TestUrls(SimpleTestCase):

    def test_home_resolves(self):
        url = reverse('home')
        self.assertEquals(resolve(url).func, home_page)

    def test_events_list_resolves(self):
        url = reverse('events_list')
        self.assertEquals(resolve(url).func, events_list)

    def test_register_page_resolves(self):
        url = reverse('register')
        self.assertEquals(resolve(url).func, register_page)

    def test_login_page_resolves(self):
        url = reverse('login')
        self.assertEquals(resolve(url).func, login_page)

    def test_logout_page_resolves(self):
        url = reverse('logout')
        self.assertEquals(resolve(url).func, logout_user)

    def test_create_event_resolves(self):
        url = reverse('create_event')
        self.assertEquals(resolve(url).func, create_event)

    def test_about_resolves(self):
        url = reverse('about')
        self.assertEquals(resolve(url).func, about)

    def test_password_reset_resolves(self):
        url = reverse('password_reset')
        self.assertEquals(resolve(url).func, password_reset_request)

    def test_users_list_resolves(self):
        url = reverse('users_list')
        self.assertEquals(resolve(url).func, users_list)

    def test_my_profile_resolves(self):
        url = reverse('my_profile')
        self.assertEquals(resolve(url).func, my_profile)

    def test_403_resolves(self):
        url = reverse('403')
        self.assertEquals(resolve(url).func, handler_403)

    def test_user_details_resolves(self):
        url = reverse('user_details', args=['1111'])
        self.assertEquals(resolve(url).func, user_details)

    def test_user_edit_resolves(self):
        url = reverse('user_edit', args=['1111'])
        self.assertEquals(resolve(url).func, user_edit)

    def test_delete_user_resolves(self):
        url = reverse('delete_user', args=['1111'])
        self.assertEquals(resolve(url).func, delete_user)

    def test_event_edit_resolves(self):
        url = reverse('event_edit', args=['1111'])
        self.assertEquals(resolve(url).func, event_edit)

    def test_delete_event_resolves(self):
        url = reverse('delete_event', args=['1111'])
        self.assertEquals(resolve(url).func, delete_event)

    def test_event_details_resolves(self):
        url = reverse('event_details', args=['1111'])
        self.assertEquals(resolve(url).func, event_details)
