#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from decouple import config as decouple_config, Config, RepositoryEnv

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'digitalorderapi.settings')

    # Load the correct .env file based on the environment
    environment = decouple_config('ENVIRONMENT', default='development')
    
    if environment == 'production':
        # Use the production .env file
        config = Config(RepositoryEnv('.env.production'))
    else:
        # Use the default .env file (for development)
        config = Config(RepositoryEnv('.env'))

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
