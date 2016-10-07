from django.contrib.auth import hashers
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView

from vault import utils
from vault.models import User, Entry


class HomeView(TemplateView):
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data()

        # Heel lelijk, maar als er geen users zijn eentje aanmaken
        if not User.objects.count():
            # Genereer group master key
            master_plain = utils.random_password(256)
            user_password = 'Welkom01'
            User.objects.create(
                username='admin',
                password=hashers.make_password(user_password),
                group_key=utils.encrypt(data=master_plain, key=user_password)
            )

        context['users'] = User.objects.all()

        return context

    def get(self, request, *args, **kwargs):
        return super(HomeView, self).get(request, *args, **kwargs)

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):

        new_username = request.POST['username']
        new_password = request.POST['password']

        current_username = request.POST['your_username']
        current_password = request.POST['your_password']

        current = User.login(username=current_username, password=current_password)
        if not current:
            return redirect('/')

        # Retrieve master key for all passwords
        group_key = utils.decrypt(data=current.group_key, key=current_password)

        # Encrypt master key for new user
        new_group_key = utils.encrypt(data=group_key, key=new_password)

        newuser = User.objects.create(
            username=new_username,
            password=hashers.make_password(new_password),
            group_key=new_group_key
        )

        return redirect('/')


class ListView(TemplateView):
    template_name = 'list.html'

    def get_context_data(self, **kwargs):
        context = super(ListView, self).get_context_data()

        context['list'] = Entry.objects.all()

        return context

    def get(self, request, *args, **kwargs):
        return super(ListView, self).get(request, *args, **kwargs)

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        current_username = request.POST['your_username']
        current_password = request.POST['your_password']

        entry_name = request.POST['name']
        entry_username = request.POST['username']
        entry_password = request.POST['password']

        current = User.login(username=current_username, password=current_password)
        if not current:
            return redirect('/list')

        # Retrieve master key for all passwords
        group_key = utils.decrypt(data=current.group_key, key=current_password)

        # Encrypt new entry before saving..
        entry_encrypted_password = Entry.encrypt_password(group_key, entry_password)

        # Save new entry
        Entry.objects.create(
            name=entry_name,
            username=entry_username,
            password=entry_encrypted_password
        )

        return redirect('/list')


class DetailView(TemplateView):
    template_name = 'detail.html'

    def get_context_data(self, **kwargs):
        context = super(DetailView, self).get_context_data(**kwargs)

        context['entry'] = Entry.objects.get(pk=kwargs.get('id'))

        return context

    def get(self, request, *args, **kwargs):

        kwargs['plain'] = '- encrypted -'

        try:
            if int(request.session['entry_id']) == int(kwargs.get('id')):
                kwargs['plain'] = request.session['entry_plain']

            del request.session['entry_plain']
            del request.session['entry_id']
            request.session.modified = True
        except:
            pass

        return super(DetailView, self).get(request, *args, **kwargs)

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        current_username = request.POST['your_username']
        current_password = request.POST['your_password']

        entry_id = request.POST['entry']
        entry = Entry.objects.get(pk=entry_id)

        current = User.login(username=current_username, password=current_password)
        if not current:
            print('User failed!')
            return redirect('/list/{}'.format(entry.pk))

        # Retrieve master key for all passwords
        group_key = utils.decrypt(data=current.group_key, key=current_password)

        # Decrypt entry password
        plain_password = entry.decrypt_password(group_key)
        print(plain_password)

        # Save password to session (not safe for production!)
        request.session['entry_id'] = entry.pk
        request.session['entry_plain'] = plain_password
        request.session.modified = True

        return redirect('/list/{}'.format(entry.pk))
