#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USERNAME "root"  // 用户改为 root
#define PASSWORD "12345678"

void handle_scp(ssh_session session) {
    printf("SCP functionality placeholder\n");
    // TODO: 实现 SCP 功能处理逻辑
}

int main() {
    ssh_bind sshbind;
    ssh_session session;
    int auth = 0;
    int port = 33284; // 端口设置为 33284

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Failed to create ssh_bind\n");
        return 1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return 1;
    }

    printf("SSH server listening on port %d\n", port);

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Failed to create session\n");
            break;
        }

        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting connection: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }

        // Authenticate user
        ssh_message message;
        while ((message = ssh_message_get(session))) {
            if (ssh_message_type(message) == SSH_REQUEST_AUTH && 
                ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                const char *user = ssh_message_auth_user(message);
                const char *pass = ssh_message_auth_password(message);

                if (strcmp(user, USERNAME) == 0 && strcmp(pass, PASSWORD) == 0) {
                    auth = 1;
                    ssh_message_auth_reply_success(message, 0);
                    printf("User %s authenticated successfully\n", user);
                } else {
                    ssh_message_auth_reply_default(message);
                }
                ssh_message_free(message);
                break;
            }
            ssh_message_free(message);
        }

        if (!auth) {
            fprintf(stderr, "Authentication failed\n");
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        // Handle SCP functionality
        handle_scp(session);

        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(sshbind);
    return 0;
}