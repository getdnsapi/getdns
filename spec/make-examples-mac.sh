rm -rf *.o *.dylib
gcc -std=c89 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c getdns_core_only.c
gcc -std=c89 -dynamiclib -fPIC -levent_core -o libgetdns.dylib getdns_core_only.o
gcc -std=c89 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-all-functions.c
gcc -std=c89 -fPIC -L./ example-all-functions.o -levent_core -lgetdns -o example-all-functions 
gcc -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-simple-answers.c
gcc -std=c99 -fPIC -L./ example-simple-answers.o -levent_core -lgetdns -o example-simple-answers 
gcc -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-tree.c
gcc -std=c99 -fPIC -L./ example-tree.o -levent_core -lgetdns -o example-tree 
gcc -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-synchronous.c
gcc -std=c99 -fPIC -L./ example-synchronous.o -levent_core -lgetdns -o example-synchronous 
rm -rf *.o *.dylib
clang -std=c89 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c getdns_core_only.c
clang -std=c89 -dynamiclib -fPIC -levent_core -o libgetdns.dylib getdns_core_only.o
clang -std=c89 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-all-functions.c
clang -std=c89 -fPIC -L./ example-all-functions.o -levent_core -lgetdns -o example-all-functions 
clang -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-simple-answers.c
clang -std=c99 -fPIC -L./ example-simple-answers.o -levent_core -lgetdns -o example-simple-answers 
clang -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-tree.c
clang -std=c99 -fPIC -L./ example-tree.o -levent_core -lgetdns -o example-tree 
clang -std=c99 -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c example-synchronous.c
clang -std=c99 -fPIC -L./ example-synchronous.o -levent_core -lgetdns -o example-synchronous 
