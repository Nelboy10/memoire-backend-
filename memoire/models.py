from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin_general', 'Administrateur Général'),
        ('admin_entite', 'Administrateur d\'Entité'),
        ('secretaire', 'Secrétaire'),
        ('etudiant', 'Étudiant'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    entite = models.ForeignKey('Entite', on_delete=models.CASCADE, null=True, blank=True)
    date_expiration = models.DateTimeField(null=True, blank=True)
    telephone = models.CharField(max_length=20, blank=True)
    
    def is_account_expired(self):
        if self.role == 'etudiant' and self.date_expiration:
            return timezone.now() > self.date_expiration
        return False
    
    def save(self, *args, **kwargs):
        # Pour les étudiants, définir la date d'expiration à 4 jours
        if self.role == 'etudiant' and not self.date_expiration:
            self.date_expiration = timezone.now() + timedelta(days=4)
        super().save(*args, **kwargs)
    def __str__(self):
        return f"{self.get_full_name()} ({self.username})" if self.get_full_name() else self.username

class Entite(models.Model):
    nom = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    administrateur = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='entites_administrees')
    
    def __str__(self):
        return self.nom

class Memoire(models.Model):
    titre = models.CharField(max_length=500)
    resume = models.TextField()
    fichier = models.FileField(upload_to='memoires/')
    auteur = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memoires')
    entite = models.ForeignKey(Entite, on_delete=models.CASCADE)
    est_public = models.BooleanField(default=True)
    nb_telechargements = models.IntegerField(default=0)
    date_soumission = models.DateTimeField(auto_now_add=True)
    annee_soumission = models.IntegerField()
    filiere = models.CharField(max_length=255)
    mots_cles = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-nb_telechargements', '-date_soumission']
    
    def __str__(self):
        return self.titre

class DownloadLog(models.Model):
    email = models.EmailField()
    memoire = models.ForeignKey(Memoire, on_delete=models.CASCADE)
    date_telechargement = models.DateTimeField(auto_now_add=True)
    entite = models.ForeignKey(Entite, on_delete=models.CASCADE)
    
    class Meta:
        ordering = ['-date_telechargement']
    
    def save(self, *args, **kwargs):
        if not self.entite_id and self.memoire:
            self.entite = self.memoire.entite
        super().save(*args, **kwargs)
    def __str__(self):
        return f"Téléchargement de {self.email} - {self.memoire.titre}"

class Statistiques(models.Model):
    entite = models.ForeignKey(Entite, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True)
    total_memoires = models.IntegerField(default=0)
    total_telechargements = models.IntegerField(default=0)
    memoires_publics = models.IntegerField(default=0)
    memoires_prives = models.IntegerField(default=0)
    
    class Meta:
        unique_together = ['entite', 'date']
    def __str__(self):
        return f"Stats {self.entite.nom} - {self.date}"