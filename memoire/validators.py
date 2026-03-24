from django.core.exceptions import ValidationError
from django.conf import settings
import os


def validate_memoire_file(value):
    """
    Validate the uploaded file for memoire submissions.
    Checks file extension and file size.
    """
    config = getattr(settings, 'MEMOIRE_CONFIG', {})
    allowed_types = config.get('ALLOWED_FILE_TYPES', ['pdf', 'doc', 'docx'])
    max_size = config.get('MAX_FILE_SIZE', 20 * 1024 * 1024)

    # Check extension
    ext = os.path.splitext(value.name)[1].lower().lstrip('.')
    if ext not in allowed_types:
        raise ValidationError(
            f"Type de fichier non autorisé. Types acceptés : {', '.join(allowed_types)}"
        )

    # Check size
    if value.size > max_size:
        max_mb = max_size / (1024 * 1024)
        raise ValidationError(
            f"Le fichier est trop volumineux. Taille maximale : {max_mb:.0f} Mo"
        )
