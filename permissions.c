#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

struct regis {
	struct in_addr ip_addr;
	char permission;
};

void usage()
{
    printf("Usage: permissions [add]|[print] HMI_ip_addr [ro]|[rw]\n");

}

int main(int argc, char *argv[])
{
	struct regis registro;
	bzero (&registro, sizeof registro);
	FILE *fp;
	if (argc < 2){
        usage();
        exit(-1);
        }
	if (!strcmp(argv[1],"add")){
        fp=fopen("permissions.dat","ab+");
        if (!fp){
            perror("fopen");
            exit(-1);
        }
        if (argc < 4) {
            usage();
            exit(-1);
        }
		registro.ip_addr.s_addr=inet_addr(argv[2]);
		if (!strcmp(argv[3],"ro"))
			registro.permission='r';
		else if (!strcmp(argv[3],"rw")){
			printf("Permiso RW\n");
			registro.permission='w';
		}
        fwrite(&registro,sizeof(registro),1,fp);
	} else {
		if (!strcmp(argv[1],"print")){
            fp=fopen("permissions.dat","rb");
            if (!fp){
                perror("fopen");
                exit(-1);
            }
			fread(&registro,sizeof(registro),1,fp);
			while (!feof(fp)){
				printf("HMI IP: %s\n",inet_ntoa(registro.ip_addr));
				if (registro.permission=='r')
					printf("HMI permissions: ro\n");
				else
					printf("HMI permissions: rw\n");
				fread(&registro,sizeof(registro),1,fp);
			}
		}
	}
	fclose(fp);
}




