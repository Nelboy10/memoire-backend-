from rest_framework import permissions

class IsAdminGeneral(permissions.BasePermission):
    """
    Permission accordée uniquement à l'administrateur général.
    """
    def has_permission(self, request, view):
        return (
            request.user 
            and request.user.is_authenticated 
            and getattr(request.user, "role", None) == "admin_general"
        )


class IsAdminEntite(permissions.BasePermission):
    """
    Permission accordée uniquement à l'administrateur d'entité.
    """
    def has_permission(self, request, view):
        return (
            request.user 
            and request.user.is_authenticated 
            and getattr(request.user, "role", None) == "admin_entite"
        )


class IsSecretaire(permissions.BasePermission):
    """
    Permission accordée uniquement au secrétaire.
    """
    def has_permission(self, request, view):
        return (
            request.user 
            and request.user.is_authenticated 
            and getattr(request.user, "role", None) == "secretaire"
        )


class IsStudent(permissions.BasePermission):
    """
    Permission accordée uniquement à un étudiant dont le compte n’est pas expiré.
    """
    def has_permission(self, request, view):
        user = request.user
        return (
            user 
            and user.is_authenticated 
            and getattr(user, "role", None) == "etudiant"
            and hasattr(user, "is_account_expired") 
            and not user.is_account_expired()
        )


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Autorise les requêtes en lecture pour tous les utilisateurs authentifiés.
    Autorise la modification uniquement pour l'auteur de l'objet.
    """
    def has_permission(self, request, view):
        # Lecture : autorisée pour tous les utilisateurs connectés
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        # Écriture : vérifiée plus bas avec has_object_permission
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Lecture : autorisée pour tous
        if request.method in permissions.SAFE_METHODS:
            return True
        # Écriture : réservée au propriétaire (auteur)
        return getattr(obj, "auteur", None) == request.user
