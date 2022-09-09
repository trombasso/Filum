import sys
sys.path.insert(0, '/var/www/kiwi_fruktsalat')
sys.path.insert(1, '/var/www/kiwi_fruktsalat/kiwi_fruktsalat')

activate_this = '/home/trombasso/.local/share/virtualenvs/kiwi_fruktsalat-OdZtOuEK/bin/activate_this.py'
with open(activate_this) as file_:
    exec(file_.read(), dict(__file__=activate_this))

from kiwi_fruktsalat import app as application
