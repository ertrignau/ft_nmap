# includes

`config.h` contient les structures et enums globaux du programme : CLI, cible, route, sockets, capture, scan et config principale.

`runtime.h` décrit le noyau d’exécution du scan : probes, états, résultats et tableau runtime.

`ft_nmap.h` expose uniquement l’API appelée par `main.c` pour assembler les étapes du programme.

Les headers restent volontairement peu nombreux pour éviter de noyer l’architecture.