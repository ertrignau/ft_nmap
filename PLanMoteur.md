# ft_nmap — Plan moteur des travaux restants

## Rôle du document

Ce document décrit uniquement la réécriture du runtime et du scheduler. Il ne redécrit pas le parsing, la résolution, l’ouverture du socket raw, l’activation de PCAP, les builders de paquets, l’affichage ou le laboratoire. Ces modules existent déjà ou sont traités dans **Plan global** ; le moteur les consomme par des interfaces stables.

---

## Décisions déjà figées

- un scheduler central possède tout l’état ;
- un seul thread lit PCAP ;
- une probe logique correspond à `cible × port × type de scan` ;
- chaque cible possède un timing TCP et un timing UDP ;
- SYN, ACK, NULL, FIN et XMAS partagent le timing TCP ;
- aucun timing n’appartient à un worker ;
- sans `--speedup`, aucun worker n’est créé ;
- avec `--speedup N`, un worker représente au maximum un message actif ;
- les workers envoient mais ne décident jamais ;
- la fenêtre initiale est de 10 pour TCP et UDP ;
- un retry de classification existe uniquement après timeout ;
- un timeout simple ne réduit pas immédiatement la fenêtre ;
- une réponse sur retry constitue une perte démontrée ;
- les timing probes dédiées de Nmap ne sont pas implémentées dans la première version ;
- aucune tentative complète n’est conservée dans un tableau fixe ;
- une réponse tardive peut classifier le job mais ne met pas à jour le RTT courant ;
- aucun timing partagé par routeur n’est prévu dans la première version.

---

## 1. Remplacer les anciennes structures runtime

Créer les nouvelles structures minimales : job logique, état de timing, runtime d’une cible, scheduler global et worker. Retirer des anciennes structures les compteurs ou états désormais possédés par le scheduler.

Le job conserve uniquement l’état courant :

```c
typedef enum e_probe_state
{
    PROBE_UNSENT,
    PROBE_DISPATCHED,
    PROBE_IN_FLIGHT,
    PROBE_RETRY_READY,
    PROBE_WAITING_RETRY_LEVEL,
    PROBE_DONE
}   t_probe_state;
```

Il contient au minimum la cible, le port, le type de scan, le résultat, le numéro de tentative, l’identité du dernier envoi, les échéances et le worker réservé.

**Fini lorsque :** aucun ancien compteur global ne concurrence les nouvelles structures.

---

## 2. Générer tous les jobs avant le scan

À partir de la configuration validée, créer un job pour chaque combinaison :

```text
cible × port × type de scan sélectionné
```

L’ordre initial peut être mélangé à l’intérieur de chaque cible, mais il doit rester reproductible en mode debug. Les résultats sont stockés séparément des jobs pour survivre à la fin du runtime.

**Fini lorsque :** le nombre de jobs est exactement calculable et chaque résultat possède un emplacement unique.

---

## 3. Figer l’identité d’une tentative

Définir un secret aléatoire propre au processus, une base de ports source et un token TCP. L’identité doit encoder suffisamment d’informations pour retrouver :

- le processus ;
- la cible ;
- le port destination ;
- le type de scan ;
- le numéro de tentative.

Pour UDP et les ICMP, le paquet cité doit permettre de retrouver le job grâce aux adresses, ports, protocole et IP ID disponibles. Pour TCP, les champs SEQ/ACK renforcent le matching.

**Fini lorsque :** une réponse de tentative ancienne reste identifiable sans conserver un objet complet par tentative.

---

## 4. Initialiser les deux timings de chaque cible

Chaque cible reçoit :

```c
timing[TIMING_GROUP_TCP]
timing[TIMING_GROUP_UDP]
```

Chaque timing contient au minimum :

- `cwnd` et `ssthresh` ;
- nombre de probes dispatched et en vol ;
- `srtt`, `rttvar` et `rto` ;
- délai entre envois et prochaine date autorisée ;
- plafond de retries ;
- plus grand retry ayant obtenu une réponse ;
- plus grand niveau actuellement autorisé ;
- compteurs de réponses, timeouts et pertes démontrées.

Initialiser `cwnd` à 10 pour les deux groupes. Les valeurs apprises par une cible ne modifient pas celles des autres cibles.

**Fini lorsque :** TCP et UDP peuvent progresser ou ralentir indépendamment pour chaque cible.

---

## 5. Écrire la sélection de la prochaine probe

Le scheduler cherche une candidate dans cet ordre logique :

1. retry déjà autorisé ;
2. job jamais envoyé ;
3. job bloqué dont le niveau vient d’être autorisé.

Une candidate ne peut partir que si :

- son groupe respecte `cwnd` ;
- le pacing autorise un envoi maintenant ;
- le plafond global est disponible ;
- un worker est disponible en mode threadé ;
- la cible n’est pas terminée.

Le parcours des cibles est round-robin pour éviter qu’une cible monopolise le moteur.

**Fini lorsque :** la fonction de sélection ne construit ni n’envoie de paquet et ne dépend pas du type précis de scan.

---

## 6. Implémenter le mode central sans workers

Lorsque `speedup == 0`, le scheduler appelle directement la fonction d’envoi déjà existante. Après succès, le job devient `PROBE_IN_FLIGHT`, ses timestamps sont enregistrés et les compteurs du timing sont mis à jour.

L’absence de workers ne limite pas le moteur à une seule probe : le scheduler continue à remplir `cwnd`, puis retourne dans `select()`.

**Fini lorsque :** plusieurs probes sont simultanément en vol sans aucun `pthread_create()`.

---

## 7. Implémenter le pool de workers

Lorsque `speedup > 0`, créer exactement `N` workers persistants. Le scheduler réserve un worker et fait passer le job à `PROBE_DISPATCHED` avant de placer la tâche dans la file.

Le worker :

1. récupère une tâche ;
2. construit ou finalise le paquet ;
3. appelle `sendto()` ;
4. publie le résultat et le timestamp ;
5. reste réservé au message jusqu’à ce que le scheduler le libère.

Le worker ne touche jamais au `cwnd`, aux retries, au résultat ou à la sélection du job suivant.

**Fini lorsque :** 250 workers peuvent exister sans modifier la logique du scheduler.

---

## 8. Ajouter le réveil du scheduler

Les workers publient leurs completions dans une file et écrivent dans un pipe surveillé par le `select()` central. Le scheduler vide le pipe, traite toutes les completions puis réalise lui-même les transitions :

```text
DISPATCHED -> IN_FLIGHT
DISPATCHED -> RETRY_READY
DISPATCHED -> DONE
```

selon le résultat du `sendto()` et la nature de l’erreur.

**Fini lorsque :** aucune attente active ni polling permanent n’est nécessaire.

---

## 9. Brancher la réception PCAP

Le scheduler reste l’unique lecteur PCAP. À chaque réveil, il vide tous les paquets immédiatement disponibles, appelle le parser/matcher existant et reçoit un événement normalisé :

```text
job identifié
tentative identifiée
type de réponse
timestamp de réception
raison de classification
```

Le moteur ne doit pas connaître la disposition binaire détaillée des headers ; cette responsabilité reste dans la couche de parsing réseau.

**Fini lorsque :** le scheduler traite de la même façon une réponse TCP, UDP ou ICMP déjà normalisée.

---

## 10. Traiter une réponse de la tentative courante

Lorsqu’une réponse valide concerne la tentative actuellement en vol :

- classifier le job ;
- enregistrer la raison ;
- mettre à jour RTT, RTO et statistiques ;
- libérer le slot de timing ;
- libérer le worker éventuel ;
- passer le job à `PROBE_DONE`.

Une réponse normale ne crée jamais de retry.

**Fini lorsque :** le chemin de succès ne dépend pas d’un timeout ultérieur pour terminer le job.

---

## 11. Traiter une réponse tardive

Si la réponse correspond à une tentative plus ancienne que `try_no` :

- classifier le job ;
- ne pas utiliser son délai comme RTT de la tentative courante ;
- annuler logiquement la tentative courante ;
- libérer son slot et son worker ;
- ignorer proprement toute réponse ultérieure du même job.

**Fini lorsque :** un retry ne peut pas maintenir un job actif après qu’une ancienne tentative a déjà répondu.

---

## 12. Expirer les probes

Une probe expire lorsque l’horloge monotone atteint `timeout_at`. Le scheduler :

- retire la tentative des probes en vol ;
- libère le worker réservé ;
- incrémente les timeouts ;
- ne réduit pas immédiatement `cwnd` ;
- décide si le prochain retry est autorisé, bloqué ou impossible.

Le timeout est calculé avec le RTO du groupe, borné par les valeurs de configuration retenues.

**Fini lorsque :** aucune probe silencieuse ne reste indéfiniment active.

---

## 13. Implémenter les niveaux de retry adaptatifs

Maintenir :

```text
max_retries
max_successful_try
allowed_try
```

Au départ, `allowed_try = 1`. Une réponse obtenue au niveau `k` permet au groupe d’autoriser au plus `k + 1`, sans dépasser `max_retries`.

À l’expiration :

- `try_no < allowed_try` : `PROBE_RETRY_READY` ;
- niveau supérieur encore susceptible d’être autorisé : `PROBE_WAITING_RETRY_LEVEL` ;
- aucun niveau futur possible : résultat final par silence.

**Fini lorsque :** les ports silencieux ne consomment pas automatiquement tous les retries maximaux.

---

## 14. Détecter une perte démontrée

Une réponse reçue sur un retry prouve qu’une tentative antérieure ou sa réponse a été perdue. Dans ce cas seulement, le moteur applique la réaction de congestion :

- incrémenter les pertes démontrées ;
- réduire `cwnd` ;
- ajuster `ssthresh` ;
- augmenter éventuellement le délai d’envoi.

Le même algorithme est utilisé pour TCP et UDP, mais sur deux états séparés et avec des plafonds de pacing éventuellement différents.

**Fini lorsque :** un port totalement silencieux n’est pas confondu avec une cible qui rate-limite ses réponses.

---

## 15. Faire évoluer la fenêtre sur les succès

Une réponse de tentative courante valide augmente la capacité du groupe. Avant `ssthresh`, la croissance est rapide ; après le seuil, elle devient progressive, par exemple avec un incrément proche de `1 / cwnd`.

Le nombre réel de probes reste entier, même si `cwnd` est stocké en flottant. La condition pratique reste :

```text
in_flight + dispatched < cwnd
```

**Fini lorsque :** une cible TCP réactive dépasse rapidement la fenêtre initiale sans rafale initiale artificielle de 50 probes.

---

## 16. Calculer la prochaine échéance de `select()`

Après chaque cycle, déterminer le plus proche événement temporel :

- prochain timeout ;
- prochain instant autorisé par le pacing ;
- éventuel déblocage d’un retry ;
- arrêt demandé.

Le `select()` surveille :

- le fd PCAP ;
- le pipe des workers ;
- cette échéance comme timeout.

Avant de dormir, le scheduler doit avoir envoyé toutes les probes actuellement autorisées.

**Fini lorsque :** le moteur ne fait ni attente active ni sommeil fixe.

---

## 17. Déterminer la fin d’un groupe et du scan

Un groupe est terminé lorsqu’il ne possède plus :

- de job jamais envoyé ;
- de retry prêt ;
- de probe dispatched ou en vol ;
- de job bloqué pouvant encore être débloqué.

Le scan est terminé lorsque tous les groupes de toutes les cibles sont terminés. Les jobs bloqués doivent être finalisés par silence lorsque plus aucun événement ne peut augmenter `allowed_try`.

**Fini lorsque :** le scheduler ne quitte ni trop tôt ni après une attente inutile.

---

## 18. Ajouter les métriques du moteur

Conserver au minimum :

- jobs total, done, unsent et blocked ;
- probes dispatched et en vol ;
- maximum simultané ;
- paquets vus et matchés ;
- timeouts ;
- retries envoyés ;
- réponses tardives ;
- pertes démontrées ;
- évolution de `cwnd`, RTO et pacing ;
- nombre maximal de workers occupés.

Ces métriques restent désactivables dans la sortie normale mais servent aux tests, au debug et à la défense du bonus technique.

**Fini lorsque :** on peut expliquer précisément pourquoi un scan accélère ou ralentit.

---

## 19. Supprimer l’ancien moteur

Une fois les tests d’intégration passés :

- retirer l’ancienne logique de scheduler ;
- supprimer les anciens états redondants ;
- supprimer les chemins d’envoi qui contournent le scheduler ;
- conserver les commentaires utiles et adapter seulement ceux devenus faux.

**Fini lorsque :** il n’existe qu’un seul chemin pour envoyer, recevoir, expirer et retry une probe.

---

# Décisions restantes à figer pendant l’implémentation

## A. Plafond de retries par défaut

L’architecture accepte une valeur configurable. Il reste à décider si la valeur par défaut de `ft_nmap` reprend les 10 retransmissions maximales de Nmap ou une valeur plus faible, sans modifier le fonctionnement adaptatif.

## B. Pacing exact TCP

Les paliers généraux sont connus, mais les seuils et le plafond TCP doivent encore être validés par lecture du code Nmap et par trace sur un laboratoire limitant les RST.

## C. Étendue de la table de payloads UDP

Le moteur accepte n’importe quelle table externe. Il reste à choisir le sous-ensemble embarqué pour la première version.

## D. Plafond global sans `--speedup`

Le mode central possède une fenêtre adaptative par cible, mais il faut fixer un plafond de sécurité global pour les fichiers contenant beaucoup de cibles.

## E. Formule définitive du token TCP et de l’IP ID

La formule doit être testée avec plusieurs scans, retries et processus simultanés avant d’être figée.

---

# Ordre d’implémentation du moteur

1. nouvelles structures ;
2. génération des jobs ;
3. identité des tentatives ;
4. timings par cible ;
5. sélection des probes ;
6. envoi central sans workers ;
7. réception et classification ;
8. timeouts et retries ;
9. congestion et pacing ;
10. fin de scan ;
11. pool de workers ;
12. équité multi-cibles ;
13. métriques ;
14. suppression de l’ancien moteur.

---

# Références du comportement Nmap

- Scheduler, retries et timing probes :  
  https://svn.nmap.org/nmap-releases/nmap-7.80/scan_engine.cc
- Contrôle de congestion et RTT :  
  https://svn.nmap.org/nmap-releases/nmap-7.80/timing.cc
- Construction et classification raw :  
  https://svn.nmap.org/nmap-releases/nmap-7.80/scan_engine_raw.cc
- Plafond de retransmissions :  
  https://svn.nmap.org/nmap-releases/nmap-7.80/nmap.h
- Payloads UDP :  
  https://svn.nmap.org/nmap-releases/nmap-7.80/payload.cc
- Documentation timing :  
  https://nmap.org/book/man-performance.html