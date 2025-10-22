# memoire/views.py
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.db.models import Q, Count
from django.db.models.functions import TruncMonth
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.http import FileResponse
import os

# Import JWT
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from .models import User, Entite, Memoire, DownloadLog, Statistiques
from .serializers import *
from .permissions import *


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def current_user(request):
    """
    Récupérer les informations de l'utilisateur connecté via JWT
    """
    user = request.user
    return Response({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_staff': user.is_staff,
        'role': user.role,
        'entite': user.entite.id if user.entite else None,
        'entite_nom': user.entite.nom if user.entite else None,
    })

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login_view(request):
    """
    Connexion avec authentification JWT
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {'error': 'Nom d\'utilisateur et mot de passe requis'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = authenticate(username=username, password=password)
    
    if user is not None:
        if user.is_active:
            # Vérifier si le compte étudiant n'est pas expiré
            if user.role == 'etudiant' and user.is_account_expired():
                return Response(
                    {'error': 'Votre compte étudiant a expiré'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Générer les tokens JWT
            refresh = RefreshToken.for_user(user)
            
            serializer = UserSerializer(user)
            return Response({
                'user': serializer.data,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': 'Connexion réussie'
            })
        else:
            return Response(
                {'error': 'Ce compte est désactivé'}, 
                status=status.HTTP_403_FORBIDDEN
            )
    else:
        return Response(
            {'error': 'Identifiants incorrects'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def logout_view(request):
    """
    Déconnexion - Blacklist le refresh token
    """
    try:
        refresh_token = request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        # Logout de la session Django (au cas où)
        logout(request)
        
        return Response({'message': 'Déconnexion réussie'})
    except Exception as e:
        return Response({'error': 'Token invalide'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_student(request):
    """
    Inscription d'un étudiant (compte temporaire) avec JWT
    """
    data = request.data.copy()
    data['role'] = 'etudiant'
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        
        # Générer les tokens JWT après l'inscription
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'message': 'Inscription réussie'
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def change_password(request):
    """
    Changer le mot de passe de l'utilisateur connecté
    """
    form = PasswordChangeForm(request.user, request.data)
    
    if form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)  # Maintient la session
        return Response({'message': 'Mot de passe modifié avec succès'})
    else:
        return Response({'error': form.errors}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def refresh_token_view(request):
    """
    Rafraîchir le token JWT
    """
    try:
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'error': 'Refresh token requis'}, status=status.HTTP_400_BAD_REQUEST)
        
        token = RefreshToken(refresh_token)
        new_access = str(token.access_token)
        
        return Response({
            'access': new_access,
            'message': 'Token rafraîchi avec succès'
        })
    except Exception as e:
        return Response({'error': 'Token invalide'}, status=status.HTTP_400_BAD_REQUEST)

# Fonctions utilitaires pour les statistiques
def get_memoires_par_mois(entite=None):
    """Récupère le nombre de mémoires par mois"""
    queryset = Memoire.objects.all()
    if entite:
        queryset = queryset.filter(entite=entite)
    
    return list(queryset.annotate(
        mois=TruncMonth('date_soumission')
    ).values('mois').annotate(
        count=Count('id')
    ).order_by('mois').values('mois', 'count'))

def get_telechargements_par_mois(entite=None):
    """Récupère le nombre de téléchargements par mois"""
    queryset = DownloadLog.objects.all()
    if entite:
        queryset = queryset.filter(entite=entite)
    
    return list(queryset.annotate(
        mois=TruncMonth('date_telechargement')
    ).values('mois').annotate(
        count=Count('id')
    ).order_by('mois').values('mois', 'count'))

@api_view(['GET'])
@permission_classes([IsAdminGeneral | IsAdminEntite])
def dashboard_stats(request):
    """
    Statistiques du dashboard selon le rôle
    """
    user = request.user
    today = timezone.now()
    
    if user.role == 'admin_general':
        # Statistiques globales
        stats = {
            'total_users': User.objects.count(),
            'total_memoires': Memoire.objects.count(),
            'total_telechargements': DownloadLog.objects.count(),
            'memoires_publics': Memoire.objects.filter(est_public=True).count(),
            'total_etudiants': User.objects.filter(role='etudiant').count(),
            'etudiants_expires': User.objects.filter(
                role='etudiant', 
                date_expiration__lt=timezone.now()
            ).count(),
            # Ajout des statistiques par mois
            'memoires_par_mois': get_memoires_par_mois(),
            'telechargements_par_mois': get_telechargements_par_mois(),
        }
    elif user.role == 'admin_entite' and user.entite:
        # Statistiques de l'entité
        entite = user.entite
        memoires_entite = Memoire.objects.filter(entite=entite)
        stats = {
            'entite': entite.nom,
            'total_memoires': memoires_entite.count(),
            'total_telechargements': DownloadLog.objects.filter(entite=entite).count(),
            'memoires_publics': memoires_entite.filter(est_public=True).count(),
            'etudiants_actifs': User.objects.filter(
                entite=entite, 
                role='etudiant',
                date_expiration__gt=timezone.now()
            ).count(),
            # Statistiques par mois pour l'entité
            'memoires_par_mois': get_memoires_par_mois(entite),
            'telechargements_par_mois': get_telechargements_par_mois(entite),
        }
    else:
        return Response({'error': 'Accès non autorisé'}, status=status.HTTP_403_FORBIDDEN)
    
    return Response(stats)

# Views pour la création de comptes administrateurs
@api_view(['POST'])
@permission_classes([IsAdminGeneral])
def creer_compte_admin_entite(request):
    """
    Créer un compte admin d'entité (admin général seulement)
    """
    data = request.data.copy()
    data['role'] = 'admin_entite'
    
    # Vérifier que l'entité est spécifiée
    if not data.get('entite'):
        return Response({'error': 'Une entité doit être spécifiée'}, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'Compte admin d\'entité créé avec succès',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAdminGeneral])
def creer_compte_secretaire(request):
    """
    Créer un compte secrétaire (admin général seulement)
    """
    data = request.data.copy()
    data['role'] = 'secretaire'
    
    # Vérifier que l'entité est spécifiée
    if not data.get('entite'):
        return Response({'error': 'Une entité doit être spécifiée'}, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'Compte secrétaire créé avec succès',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAdminGeneral])
def creer_compte_admin_general(request):
    """
    Créer un compte admin général (admin général seulement)
    """
    data = request.data.copy()
    data['role'] = 'admin_general'
    
    # Les admin généraux n'ont pas d'entité
    if data.get('entite'):
        data['entite'] = None
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'Compte admin général créé avec succès',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAdminEntite])
def creer_compte_secretaire_entite(request):
    """
    Créer un compte secrétaire pour son entité (admin d'entité seulement)
    """
    if not request.user.entite:
        return Response({'error': 'Admin non assigné à une entité'}, status=status.HTTP_400_BAD_REQUEST)
    
    data = request.data.copy()
    data['role'] = 'secretaire'
    data['entite'] = request.user.entite.id  # Forcer l'entité de l'admin
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'Compte secrétaire créé avec succès pour votre entité',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ViewSets
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get_permissions(self):
        if self.action == 'create':
            # Seul l'admin général peut créer des comptes via l'API standard
            permission_classes = [IsAdminGeneral]
        else:
            permission_classes = [IsAdminGeneral | IsAdminEntite]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin_general':
            return User.objects.all()
        elif user.role == 'admin_entite':
            # L'admin d'entité ne voit que les utilisateurs de son entité (sauf admin_general)
            return User.objects.filter(
                Q(entite=user.entite) | Q(role='admin_general')
            ).distinct()
        return User.objects.none()
    
    def perform_create(self, serializer):
        # S'assurer que seul l'admin général peut créer des comptes via cette route
        if self.request.user.role != 'admin_general':
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Seul l'admin général peut créer des comptes via cette route")
        serializer.save()
    
    @action(detail=False, methods=['get'])
    def expired_students(self, request):
        """Liste des étudiants expirés (admin général et admin entité)"""
        user = request.user
        queryset = User.objects.filter(role='etudiant', date_expiration__lt=timezone.now())
        
        if user.role == 'admin_entite' and user.entite:
            queryset = queryset.filter(entite=user.entite)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['patch'])
    def update_profile(self, request, pk=None):
        """Mettre à jour le profil de l'utilisateur"""
        if not request.user.is_authenticated or request.user.id != int(pk):
            return Response(
                {'error': 'Non autorisé'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = self.get_object()
        serializer = UserSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Récupérer les informations de l'utilisateur connecté"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

class EntiteViewSet(viewsets.ModelViewSet):
    queryset = Entite.objects.all()
    serializer_class = EntiteSerializer
    permission_classes = [IsAdminGeneral]

class MemoireViewSet(viewsets.ModelViewSet):
    queryset = Memoire.objects.all()
    serializer_class = MemoireSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'search', 'public', 'download']:
            permission_classes = [permissions.AllowAny]
        elif self.action == 'create':
            permission_classes = [IsStudent]
        else:
            permission_classes = [IsAdminGeneral | IsAdminEntite | IsSecretaire | IsOwnerOrReadOnly]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        user = self.request.user
        queryset = Memoire.objects.filter(est_public=True)  # Seulement les mémoires publics par défaut
        
        # Si l'utilisateur est authentifié et a des privilèges, on peut voir plus
        if user.is_authenticated:
            if user.role == 'admin_general':
                queryset = Memoire.objects.all()
            elif user.role in ['admin_entite', 'secretaire']:
                queryset = Memoire.objects.filter(entite=user.entite)
            elif user.role == 'etudiant':
                queryset = Memoire.objects.filter(Q(est_public=True) | Q(auteur=user))
        
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(auteur=self.request.user, entite=self.request.user.entite)
    
    @action(detail=True, methods=['post'], permission_classes=[permissions.AllowAny])
    def download(self, request, pk=None):
        """
        Télécharger un mémoire - Envoi par email avec le fichier en pièce jointe
        Accessible à tous (même non authentifiés)
        """
        memoire = self.get_object()
        email = request.data.get('email')
        
        if not email:
            return Response({'error': 'Email requis'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Log du téléchargement
        DownloadLog.objects.create(
            email=email,
            memoire=memoire,
            entite=memoire.entite
        )
        
        # Incrémenter le compteur de téléchargements
        memoire.nb_telechargements += 1
        memoire.save()
        
        # Obtenir le chemin absolut du fichier
        file_path = memoire.fichier.path
        
        # Vérifier que le fichier existe
        if not os.path.exists(file_path):
            return Response({'error': 'Fichier non trouvé'}, status=status.HTTP_404_NOT_FOUND)
        
        # Envoyer le fichier par email
        try:
            subject = f'Téléchargement du mémoire - {memoire.titre}'
            
            # Template HTML pour l'email
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #3b82f6; color: white; padding: 20px; text-align: center; }}
                    .content {{ background: #f9fafb; padding: 20px; }}
                    .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #6b7280; }}
                    .memoire-info {{ background: white; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>📚 Bibliothèque de Mémoires</h1>
                    </div>
                    
                    <div class="content">
                        <h2>Votre mémoire est en pièce jointe</h2>
                        <p>Bonjour,</p>
                        <p>Vous avez demandé à télécharger le mémoire suivant :</p>
                        
                        <div class="memoire-info">
                            <h3 style="margin: 0; color: #3b82f6;">{memoire.titre}</h3>
                            <p><strong>Auteur :</strong> {memoire.auteur.get_full_name() or memoire.auteur.username}</p>
                            <p><strong>Filière :</strong> {memoire.filiere}</p>
                            <p><strong>Année :</strong> {memoire.annee_soumission}</p>
                            <p><strong>Résumé :</strong> {memoire.resume[:200]}...</p>
                        </div>
                        
                        <p>Le fichier du mémoire est attaché à cet email. Vous pouvez le télécharger et le consulter.</p>
                        
                        <p><strong>Important :</strong> Ce fichier est destiné à un usage personnel.</p>
                    </div>
                    
                    <div class="footer">
                        <p>Cet email a été envoyé à {email} suite à votre demande de téléchargement.</p>
                        <p>© 2025 Bibliothèque de Mémoires. Tous droits réservés.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            plain_message = f"""
            Téléchargement du mémoire - {memoire.titre}
            
            Bonjour,
            
            Vous avez demandé à télécharger le mémoire suivant :
            
            Titre: {memoire.titre}
            Auteur: {memoire.auteur.get_full_name() or memoire.auteur.username}
            Filière: {memoire.filiere}
            Année: {memoire.annee_soumission}
            
            Le fichier du mémoire est attaché à cet email.
            
            Important: Ce fichier est destiné à un usage personnel.
            
            © 2025 Bibliothèque de Mémoires. Tous droits réservés.
            """
            
            # Lire le fichier
            with open(file_path, 'rb') as file:
                file_data = file.read()
                file_name = os.path.basename(file_path)
                
                # Envoyer l'email avec la pièce jointe
                email_msg = EmailMessage(
                    subject,
                    plain_message,
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                )
                email_msg.attach(file_name, file_data, 'application/pdf')
                # Ajouter le contenu HTML
                email_msg.content_subtype = "html"
                email_msg.body = html_message
                email_msg.send()
            
            return Response({
                'message': f'Le mémoire a été envoyé à {email}',
                'email_sent': True,
            })
            
        except Exception as e:
            return Response({
                'message': f'Erreur lors de l\'envoi du mémoire: {str(e)}',
                'email_sent': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.AllowAny])
    def search(self, request):
        """
        Recherche de mémoires - Accessible à tous
        """
        query = request.GET.get('q', '')
        filiere = request.GET.get('filiere', '')
        annee = request.GET.get('annee', '')
        entite_id = request.GET.get('entite', '')
        
        queryset = self.get_queryset()  # Utilise get_queryset qui filtre déjà les mémoires publics
        
        if query:
            queryset = queryset.filter(
                Q(titre__icontains=query) |
                Q(resume__icontains=query) |
                Q(mots_cles__icontains=query) |
                Q(auteur__first_name__icontains=query) |
                Q(auteur__last_name__icontains=query)
            )
        
        if filiere:
            queryset = queryset.filter(filiere__icontains=filiere)
        
        if annee:
            queryset = queryset.filter(annee_soumission=annee)
        
        if entite_id:
            queryset = queryset.filter(entite_id=entite_id)
        
        # Trier par popularité et date
        queryset = queryset.order_by('-nb_telechargements', '-date_soumission')
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.AllowAny])
    def public(self, request):
        """Liste des mémoires publics pour les visiteurs"""
        public_memoires = Memoire.objects.filter(est_public=True).order_by('-nb_telechargements', '-date_soumission')
        
        page = self.paginate_queryset(public_memoires)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(public_memoires, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], permission_classes=[IsStudent])
    def mes_memoires(self, request):
        """Liste des mémoires de l'étudiant connecté"""
        if request.user.is_account_expired():
            return Response({'error': 'Compte expiré'}, status=status.HTTP_403_FORBIDDEN)
        
        memoires = Memoire.objects.filter(auteur=request.user).order_by('-date_soumission')
        serializer = self.get_serializer(memoires, many=True)
        return Response(serializer.data)

class DownloadLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DownloadLog.objects.all()
    serializer_class = DownloadLogSerializer
    permission_classes = [IsAdminGeneral | IsAdminEntite | IsSecretaire]
    
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin_general':
            return DownloadLog.objects.all()
        elif user.role in ['admin_entite', 'secretaire']:
            return DownloadLog.objects.filter(entite=user.entite)
        return DownloadLog.objects.none()

class StatistiquesViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Statistiques.objects.all()
    serializer_class = StatistiquesSerializer
    permission_classes = [IsAdminGeneral | IsAdminEntite]
    
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin_general':
            return Statistiques.objects.all()
        elif user.role == 'admin_entite':
            return Statistiques.objects.filter(entite=user.entite)
        return Statistiques.objects.none()
    
    @action(detail=False, methods=['get'])
    def global_stats(self, request):
        total_memoires = Memoire.objects.count()
        total_telechargements = DownloadLog.objects.count()
        memoires_publics = Memoire.objects.filter(est_public=True).count()
        total_etudiants = User.objects.filter(role='etudiant').count()
        
        return Response({
            'total_memoires': total_memoires,
            'total_telechargements': total_telechargements,
            'memoires_publics': memoires_publics,
            'total_etudiants': total_etudiants,
        })

# Vue pour le téléchargement direct
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def telecharger_memoire_direct(request, memoire_id):
    """
    Téléchargement direct d'un mémoire (sans email)
    Accessible à tous les utilisateurs, même non authentifiés
    """
    try:
        memoire = Memoire.objects.get(id=memoire_id, est_public=True)
    except Memoire.DoesNotExist:
        return Response({'error': 'Mémoire non trouvé ou non public'}, status=status.HTTP_404_NOT_FOUND)
    
    file_path = memoire.fichier.path
    
    if not os.path.exists(file_path):
        return Response({'error': 'Fichier non trouvé'}, status=status.HTTP_404_NOT_FOUND)
    
    # Log du téléchargement (si email fourni en paramètre)
    email = request.GET.get('email')
    if email:
        DownloadLog.objects.create(
            email=email,
            memoire=memoire,
            entite=memoire.entite
        )
    
    # Incrémenter le compteur
    memoire.nb_telechargements += 1
    memoire.save()
    
    # Retourner le fichier
    response = FileResponse(open(file_path, 'rb'))
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
    return response

# Views spécifiques pour la secrétaire
@api_view(['GET'])
@permission_classes([IsSecretaire])
def secretaire_dashboard(request):
    """
    Dashboard spécifique pour la secrétaire
    """
    if not request.user.entite:
        return Response({'error': 'Secrétaire non assignée à une entité'}, status=status.HTTP_400_BAD_REQUEST)
    
    entite = request.user.entite
    today = timezone.now()
    
    # Mémoires en attente de validation
    memoires_en_attente = Memoire.objects.filter(
        entite=entite,
        est_public=False
    ).count()
    
    # Mémoires déposés ce mois
    debut_mois = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    memoires_ce_mois = Memoire.objects.filter(
        entite=entite,
        date_soumission__gte=debut_mois
    ).count()
    
    # Téléchargements ce mois
    telechargements_ce_mois = DownloadLog.objects.filter(
        entite=entite,
        date_telechargement__gte=debut_mois
    ).count()
    
    # Étudiants actifs (comptes non expirés)
    etudiants_actifs = User.objects.filter(
        entite=entite,
        role='etudiant',
        date_expiration__gt=today,
        is_active=True
    ).count()
    
    # Étudiants expirés récemment (7 derniers jours)
    date_limite_expiration = today - timedelta(days=7)
    etudiants_expires_recent = User.objects.filter(
        entite=entite,
        role='etudiant',
        date_expiration__gte=date_limite_expiration,
        date_expiration__lt=today
    ).count()
    
    stats = {
        'entite': entite.nom,
        'memoires_en_attente': memoires_en_attente,
        'memoires_ce_mois': memoires_ce_mois,
        'telechargements_ce_mois': telechargements_ce_mois,
        'etudiants_actifs': etudiants_actifs,
        'etudiants_expires_recent': etudiants_expires_recent,
        'total_memoires': Memoire.objects.filter(entite=entite).count(),
    }
    
    return Response(stats)

@api_view(['GET'])
@permission_classes([IsSecretaire])
def memoires_en_attente(request):
    """
    Liste des mémoires en attente de validation pour la secrétaire
    """
    if not request.user.entite:
        return Response({'error': 'Secrétaire non assignée à une entité'}, status=status.HTTP_400_BAD_REQUEST)
    
    memoires = Memoire.objects.filter(
        entite=request.user.entite,
        est_public=False
    ).order_by('-date_soumission')
    
    serializer = MemoireSerializer(memoires, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsSecretaire])
def valider_memoire(request, memoire_id):
    """
    Valider un mémoire (le rendre public)
    """
    try:
        memoire = Memoire.objects.get(
            id=memoire_id,
            entite=request.user.entite
        )
    except Memoire.DoesNotExist:
        return Response({'error': 'Mémoire non trouvé'}, status=status.HTTP_404_NOT_FOUND)
    
    memoire.est_public = True
    memoire.save()
    
    return Response({
        'message': 'Mémoire validé avec succès',
        'memoire': MemoireSerializer(memoire).data
    })

@api_view(['POST'])
@permission_classes([IsSecretaire])
def rejeter_memoire(request, memoire_id):
    """
    Rejeter un mémoire (suppression)
    """
    try:
        memoire = Memoire.objects.get(
            id=memoire_id,
            entite=request.user.entite,
            est_public=False
        )
    except Memoire.DoesNotExist:
        return Response({'error': 'Mémoire non trouvé'}, status=status.HTTP_404_NOT_FOUND)
    
    titre = memoire.titre
    memoire.delete()
    
    return Response({'message': 'Mémoire rejeté avec succès'})

@api_view(['POST'])
@permission_classes([IsSecretaire])
def creer_compte_etudiant(request):
    """
    Créer un compte étudiant temporaire (4 jours)
    """
    if not request.user.entite:
        return Response({'error': 'Secrétaire non assignée à une entité'}, status=status.HTTP_400_BAD_REQUEST)
    
    data = request.data.copy()
    data['role'] = 'etudiant'
    data['entite'] = request.user.entite.id
    data['date_expiration'] = timezone.now() + timedelta(days=4)
    
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        user = serializer.save()
        
        return Response({
            'message': 'Compte étudiant créé avec succès',
            'user': UserSerializer(user).data,
            'date_expiration': user.date_expiration
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsSecretaire])
def etudiants_expires(request):
    """
    Liste des comptes étudiants expirés
    """
    if not request.user.entite:
        return Response({'error': 'Secrétaire non assignée à une entité'}, status=status.HTTP_400_BAD_REQUEST)
    
    etudiants_expires = User.objects.filter(
        entite=request.user.entite,
        role='etudiant',
        date_expiration__lt=timezone.now()
    ).order_by('-date_expiration')
    
    serializer = UserSerializer(etudiants_expires, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsSecretaire])
def prolonger_compte(request, user_id):
    """
    Prolonger un compte étudiant de 4 jours supplémentaires
    """
    try:
        etudiant = User.objects.get(
            id=user_id,
            entite=request.user.entite,
            role='etudiant'
        )
    except User.DoesNotExist:
        return Response({'error': 'Étudiant non trouvé'}, status=status.HTTP_404_NOT_FOUND)
    
    # Prolonger de 4 jours
    etudiant.date_expiration = timezone.now() + timedelta(days=4)
    etudiant.save()
    
    return Response({
        'message': 'Compte prolongé avec succès',
        'nouvelle_date_expiration': etudiant.date_expiration,
        'user': UserSerializer(etudiant).data
    })

# Views spécifiques pour l'étudiant
@api_view(['GET'])
@permission_classes([IsStudent])
def etudiant_dashboard(request):
    """
    Dashboard spécifique pour l'étudiant
    """
    today = timezone.now()
    
    # Vérifier si le compte est expiré
    if request.user.is_account_expired():
        return Response({
            'error': 'Votre compte a expiré',
            'date_expiration': request.user.date_expiration
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Mémoires déposés par l'étudiant
    mes_memoires = Memoire.objects.filter(auteur=request.user).count()
    
    # Mémoires publics de l'étudiant
    mes_memoires_publics = Memoire.objects.filter(
        auteur=request.user,
        est_public=True
    ).count()
    
    # Total des téléchargements des mémoires de l'étudiant
    total_telechargements = Memoire.objects.filter(
        auteur=request.user
    ).aggregate(total=Count('nb_telechargements'))['total'] or 0
    
    # Dernier mémoire déposé
    dernier_memoire = Memoire.objects.filter(auteur=request.user).order_by('-date_soumission').first()
    
    stats = {
        'mes_memoires': mes_memoires,
        'mes_memoires_publics': mes_memoires_publics,
        'total_telechargements': total_telechargements,
        'jours_restants': (request.user.date_expiration - today).days if request.user.date_expiration else 0,
        'date_expiration': request.user.date_expiration,
        'dernier_memoire': MemoireSerializer(dernier_memoire).data if dernier_memoire else None
    }
    
    return Response(stats)

@api_view(['GET'])
@permission_classes([IsStudent])
def mes_memoires_view(request):
    """
    Liste des mémoires déposés par l'étudiant connecté
    """
    if request.user.is_account_expired():
        return Response({'error': 'Compte expiré'}, status=status.HTTP_403_FORBIDDEN)
    
    memoires = Memoire.objects.filter(auteur=request.user).order_by('-date_soumission')
    serializer = MemoireSerializer(memoires, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsStudent])
def deposer_memoire(request):
    """
    Déposer un nouveau mémoire (étudiant)
    """
    if request.user.is_account_expired():
        return Response({'error': 'Compte expiré'}, status=status.HTTP_403_FORBIDDEN)
    
    data = request.data.copy()
    # Ne pas ajouter auteur dans les données, il sera passé au serializer via le contexte
    data['entite'] = request.user.entite.id
    
    serializer = MemoireSerializer(data=data, context={'request': request})
    
    if serializer.is_valid():
        try:
            # Sauvegarder avec l'utilisateur courant comme auteur
            memoire = serializer.save(auteur=request.user)
            
            # Par défaut, le mémoire n'est pas public (doit être validé par la secrétaire)
            # Utiliser la valeur du formulaire ou False par défaut
            est_public = data.get('est_public', 'false').lower() == 'true'
            memoire.est_public = est_public
            memoire.save()
            
            return Response({
                'message': 'Mémoire déposé avec succès. En attente de validation.',
                'memoire': MemoireSerializer(memoire).data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la sauvegarde: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsStudent])
def statistiques_personnelles(request):
    """
    Statistiques de téléchargement des mémoires de l'étudiant
    """
    if request.user.is_account_expired():
        return Response({'error': 'Compte expiré'}, status=status.HTTP_403_FORBIDDEN)
    
    # Mémoires avec leurs statistiques
    memoires = Memoire.objects.filter(auteur=request.user).order_by('-nb_telechargements')
    
    stats = {
        'total_memoires': memoires.count(),
        'total_telechargements': sum(m.nb_telechargements for m in memoires),
        'memoires_publics': memoires.filter(est_public=True).count(),
        'memoires_par_popularite': MemoireSerializer(memoires, many=True).data
    }
    
    return Response(stats)