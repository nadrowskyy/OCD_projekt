from schedule.forms import ChangePassword
from django.test import TestCase
from django.contrib.auth.models import User


class Test_ChangePassword(TestCase):

    def test_ChangePassword_valid_data(self):
        print('8888888')
        user1 = User.objects.create(
            username='Username',
            first_name='Jhon',
            last_name='Doe',
            email='example@com',
            password='Password'
        )
        form = ChangePassword(user=user1, data={
            'old_password': 'testing',
            'new_password1': 'testing'
        })
