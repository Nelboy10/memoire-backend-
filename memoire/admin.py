# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Entite, Memoire, DownloadLog, Statistiques
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone

# Personnalisation de l'admin pour le modèle User
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'entite', 'is_active', 'is_expired_display', 'date_expiration')
    list_filter = ('role', 'entite', 'is_active', 'date_expiration')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'entite', 'date_expiration', 'telephone')
        }),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'entite', 'date_expiration', 'telephone')
        }),
    )
    
    def is_expired_display(self, obj):
        if obj.role == 'etudiant' and obj.is_account_expired():
            return format_html('<span style="color: red; font-weight: bold;">⚠ EXPIRÉ</span>')
        elif obj.role == 'etudiant':
            return format_html('<span style="color: green;">✓ Actif</span>')
        return format_html('<span style="color: blue;">-</span>')
    is_expired_display.short_description = 'Statut'
    is_expired_display.admin_order_field = 'date_expiration'

class EntiteAdmin(admin.ModelAdmin):
    list_display = ('nom', 'administrateur_link', 'description', 'memoires_count', 'users_count', 'administrateurs_count')
    list_filter = ('nom',)
    search_fields = ('nom', 'description', 'administrateur__username', 'administrateur__email')
    raw_id_fields = ('administrateur',)
    
    def administrateur_link(self, obj):
        if obj.administrateur:
            url = reverse('admin:memoire_user_change', args=[obj.administrateur.id])
            return format_html('<a href="{}">{}</a>', url, obj.administrateur.get_full_name() or obj.administrateur.username)
        return format_html('<span style="color: orange;">⏳ Non assigné</span>')
    administrateur_link.short_description = 'Administrateur'
    
    def memoires_count(self, obj):
        count = Memoire.objects.filter(entite=obj).count()
        url = reverse('admin:memoire_memoire_changelist') + f'?entite__id__exact={obj.id}'
        return format_html('<a href="{}">{}</a>', url, count)
    memoires_count.short_description = 'Mémoires'
    
    def users_count(self, obj):
        count = User.objects.filter(entite=obj).count()
        url = reverse('admin:memoire_user_changelist') + f'?entite__id__exact={obj.id}'
        return format_html('<a href="{}">{}</a>', url, count)
    users_count.short_description = 'Utilisateurs'
    
    def administrateurs_count(self, obj):
        count = User.objects.filter(entite=obj, role__in=['admin_entite', 'secretaire']).count()
        url = reverse('admin:memoire_user_changelist') + f'?entite__id__exact={obj.id}&role__in=admin_entite,secretaire'
        return format_html('<a href="{}">{}</a>', url, count)
    administrateurs_count.short_description = 'Admins/Secrétaires'

class MemoireAdmin(admin.ModelAdmin):
    list_display = ('titre', 'auteur_link', 'entite_link', 'est_public', 'nb_telechargements', 'date_soumission', 'annee_soumission')
    list_filter = ('est_public', 'entite', 'annee_soumission', 'filiere', 'date_soumission')
    search_fields = ('titre', 'resume', 'auteur__first_name', 'auteur__last_name', 'filiere', 'mots_cles')
    readonly_fields = ('nb_telechargements', 'date_soumission')
    list_editable = ('est_public',)
    date_hierarchy = 'date_soumission'
    raw_id_fields = ('auteur', 'entite')
    
    fieldsets = (
        ('Informations générales', {
            'fields': ('titre', 'resume', 'fichier', 'auteur', 'entite')
        }),
        ('Métadonnées', {
            'fields': ('est_public', 'filiere', 'annee_soumission', 'mots_cles')
        }),
        ('Statistiques', {
            'fields': ('nb_telechargements', 'date_soumission'),
            'classes': ('collapse',)
        }),
    )
    
    def auteur_link(self, obj):
        if obj.auteur:
            url = reverse('admin:memoire_user_change', args=[obj.auteur.id])
            return format_html('<a href="{}">{}</a>', url, obj.auteur.get_full_name() or obj.auteur.username)
        return "-"
    auteur_link.short_description = 'Auteur'
    
    def entite_link(self, obj):
        if obj.entite:
            url = reverse('admin:memoire_entite_change', args=[obj.entite.id])
            return format_html('<a href="{}">{}</a>', url, obj.entite.nom)
        return "-"
    entite_link.short_description = 'Entité'

class DownloadLogAdmin(admin.ModelAdmin):
    list_display = ('email', 'memoire_link', 'entite_link', 'date_telechargement')
    list_filter = ('entite', 'date_telechargement')
    search_fields = ('email', 'memoire__titre')
    readonly_fields = ('date_telechargement',)
    date_hierarchy = 'date_telechargement'
    raw_id_fields = ('memoire', 'entite')
    
    def memoire_link(self, obj):
        if obj.memoire:
            url = reverse('admin:memoire_memoire_change', args=[obj.memoire.id])
            return format_html('<a href="{}">{}</a>', url, obj.memoire.titre)
        return "-"
    memoire_link.short_description = 'Mémoire'
    
    def entite_link(self, obj):
        if obj.entite:
            url = reverse('admin:memoire_entite_change', args=[obj.entite.id])
            return format_html('<a href="{}">{}</a>', url, obj.entite.nom)
        return "-"
    entite_link.short_description = 'Entité'

class StatistiquesAdmin(admin.ModelAdmin):
    list_display = ('entite_link', 'date', 'total_memoires', 'total_telechargements', 'memoires_publics', 'memoires_prives')
    list_filter = ('entite', 'date')
    readonly_fields = ('date',)
    date_hierarchy = 'date'
    
    def entite_link(self, obj):
        if obj.entite:
            url = reverse('admin:memoire_entite_change', args=[obj.entite.id])
            return format_html('<a href="{}">{}</a>', url, obj.entite.nom)
        return "Global"
    entite_link.short_description = 'Entité'

# Actions personnalisées pour l'admin
@admin.action(description="Rendre les mémoires sélectionnés publics")
def make_public(modeladmin, request, queryset):
    queryset.update(est_public=True)
    modeladmin.message_user(request, f"{queryset.count()} mémoires rendus publics.")

@admin.action(description="Rendre les mémoires sélectionnés privés")
def make_private(modeladmin, request, queryset):
    queryset.update(est_public=False)
    modeladmin.message_user(request, f"{queryset.count()} mémoires rendus privés.")

@admin.action(description="Prolonger les comptes étudiants de 4 jours")
def extend_student_accounts(modeladmin, request, queryset):
    from datetime import timedelta
    extended_count = 0
    for user in queryset:
        if user.role == 'etudiant':
            user.date_expiration = timezone.now() + timedelta(days=4)
            user.save()
            extended_count += 1
    modeladmin.message_user(request, f"{extended_count} comptes étudiants prolongés de 4 jours.")

@admin.action(description="Activer les utilisateurs sélectionnés")
def activate_users(modeladmin, request, queryset):
    queryset.update(is_active=True)
    modeladmin.message_user(request, f"{queryset.count()} utilisateurs activés.")

@admin.action(description="Désactiver les utilisateurs sélectionnés")
def deactivate_users(modeladmin, request, queryset):
    queryset.update(is_active=False)
    modeladmin.message_user(request, f"{queryset.count()} utilisateurs désactivés.")

@admin.action(description="Assigner comme admin d'entité")
def assign_as_entite_admin(modeladmin, request, queryset):
    for user in queryset:
        user.role = 'admin_entite'
        user.save()
    modeladmin.message_user(request, f"{queryset.count()} utilisateurs assignés comme admin d'entité.")

# Ajouter les actions aux admins
MemoireAdmin.actions = [make_public, make_private]
CustomUserAdmin.actions = [extend_student_accounts, activate_users, deactivate_users, assign_as_entite_admin]

# Enregistrement des modèles dans l'admin
admin.site.register(User, CustomUserAdmin)
admin.site.register(Entite, EntiteAdmin)
admin.site.register(Memoire, MemoireAdmin)
admin.site.register(DownloadLog, DownloadLogAdmin)
admin.site.register(Statistiques, StatistiquesAdmin)

# Personnalisation du header de l'admin
admin.site.site_header = "Administration du Système de Mémoires"
admin.site.site_title = "Système de Mémoires"
admin.site.index_title = "Tableau de bord"