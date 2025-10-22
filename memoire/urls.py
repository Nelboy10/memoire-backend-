# memoire/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'entites', views.EntiteViewSet)
router.register(r'memoires', views.MemoireViewSet)
router.register(r'downloads', views.DownloadLogViewSet)
router.register(r'statistiques', views.StatistiquesViewSet)

urlpatterns = [
    # Authentification JWT
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('auth/token/custom-refresh/', views.refresh_token_view, name='token_custom_refresh'),
    
    # Authentification personnalisée
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/current-user/', views.current_user, name='current_user'),
    path('auth/register-student/', views.register_student, name='register_student'),
    path('auth/password/change/', views.change_password, name='change_password'),  
    
    # Administration
    path('admin/creer-admin-entite/', views.creer_compte_admin_entite, name='creer_admin_entite'),
    path('admin/creer-secretaire/', views.creer_compte_secretaire, name='creer_secretaire'),
    path('admin/creer-admin-general/', views.creer_compte_admin_general, name='creer_admin_general'),
    path('admin/creer-secretaire-entite/', views.creer_compte_secretaire_entite, name='creer_secretaire_entite'),
    
    # Dashboard
    path('dashboard/stats/', views.dashboard_stats, name='dashboard_stats'),
    
    # Secrétaire
    path('secretaire/dashboard/', views.secretaire_dashboard, name='secretaire_dashboard'),
    path('secretaire/memoires-en-attente/', views.memoires_en_attente, name='memoires_en_attente'),
    path('secretaire/valider-memoire/<int:memoire_id>/', views.valider_memoire, name='valider_memoire'),
    path('secretaire/rejeter-memoire/<int:memoire_id>/', views.rejeter_memoire, name='rejeter_memoire'),
    path('secretaire/creer-compte-etudiant/', views.creer_compte_etudiant, name='creer_compte_etudiant'),
    path('secretaire/etudiants-expires/', views.etudiants_expires, name='etudiants_expires'),
    path('secretaire/prolonger-compte/<int:user_id>/', views.prolonger_compte, name='prolonger_compte'),
    
    # Étudiant
    path('etudiant/dashboard/', views.etudiant_dashboard, name='etudiant_dashboard'),
    path('etudiant/mes-memoires/', views.mes_memoires_view, name='mes_memoires'),
    path('etudiant/deposer-memoire/', views.deposer_memoire, name='deposer_memoire'),
    path('etudiant/statistiques/', views.statistiques_personnelles, name='statistiques_personnelles'),
    
    # Téléchargement public
    path('public/memoires/<int:memoire_id>/telecharger/', views.telecharger_memoire_direct, name='telecharger_direct'),
    
    # API ViewSets
    path('', include(router.urls)),
    
    # Interface d'administration DRF (optionnel)
    path('api-auth/', include('rest_framework.urls')),
]

# Ajout d'un namespace pour les URLs de l'application
app_name = 'memoire'