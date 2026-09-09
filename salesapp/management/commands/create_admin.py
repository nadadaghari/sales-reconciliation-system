from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from salesapp.models import UserProfile


class Command(BaseCommand):
    help = 'Create the first Admin user (with an Admin role profile) to bootstrap the system.'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)

    def handle(self, *args, **options):
        username = options['username']
        password = options['password']

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.ERROR(f'User "{username}" already exists.'))
            return

        user = User.objects.create_user(username=username, password=password, is_staff=True, is_superuser=True)
        UserProfile.objects.create(user=user, role='admin')
        self.stdout.write(self.style.SUCCESS(
            f'Admin user "{username}" created. Log in at /login/ to manage users and branches.'
        ))
