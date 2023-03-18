/* 

   nnrpkrb5auth

   Christopher P. Lindsey
   http://www.mallorn.com/tools/nnrpkrb5auth

   26jul01

   This program takes a username and password pair on STDIN and
   checks their validity against a Kerberos V password.

   Commandline options:

      --instance=[instance]

        appends /[instance] to the username prior to authentication


   Special thanks to Von Welch <vwelch@vwelch.com> for giving me 
      the initial code on which the Kerberos V authentication is based
      many years ago, and for introducing me to Kerberos back in '96.

   Also, thanks to Graeme Mathieson <graeme@mathie.cx> for his 
      inspiration through the pamckpasswd program.

*/

#include <stdio.h>
#include <string.h>
#include <krb5.h>
#include <com_err.h>

#define NAMESTR "ClientAuthname: "
#define PASSSTR "ClientPassword: "
#define INSTANCE "--instance="
#define MAX_BUF 1024


#define KRB5_DEFAULT_TICKET_OPTIONS 0

/*
 * Default life of the ticket we are getting. Since we are just checking
 * to see if the user can get one, it doesn't need a long lifetime.
 */
#define KRB5_DEFAULT_LIFE    60 * 5 /* 5 minutes */


int krb5_check_password (char *principal_name, char *password) {
   krb5_context      kcontext;
   krb5_ccache       ccache = NULL;      /* Don't use a cache */
   krb5_creds        creds;
   krb5_principal    user_principal;
   krb5_data         *user_realm;
   krb5_principal    service_principal;
   krb5_timestamp    now;
   krb5_address      **addrs = (krb5_address **) NULL;   /* Use default */
   long              lifetime = KRB5_DEFAULT_LIFE;
   int               options = KRB5_DEFAULT_TICKET_OPTIONS;

   /* TGT service name for convenience */
   krb5_data         tgtname = { 0, KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME };

   krb5_preauthtype  *preauth = NULL;

   krb5_error_code   code;

   /* Name things are logged with */
   char              *my_name = "krb5_check_password";

   /* Our return code - 1 is success */
   int                result = 0;
   
   /* Initialize our Kerberos state */
   code = krb5_init_context (&kcontext);

   if (code) {
       com_err (my_name, code, "initializing Kerberos 5 context");
       return 0;
   }
   
   /* Initialize krb5 error tables */    
   krb5_init_ets (kcontext);

   /* Get current time */
   code = krb5_timeofday (kcontext, &now);
   
   if (code) {
       com_err (my_name, code, "krb5_timeofday(): Getting time of day");
       return 0;
   }

   /* Set up credentials to be filled in */
   memset ((char *) &creds, 0, sizeof(creds));

   /* From here on, goto cleanup to exit */

   /* Parse the username into a krb5 principal */
   if (!principal_name) {
       com_err (my_name, 0, "Passed NULL principal name");
       goto cleanup;
   }

   code = krb5_parse_name (kcontext, principal_name, &user_principal);
   
   if (code) {
       com_err (my_name, code, "parsing user principal name %.100s",
                principal_name);
       goto cleanup;
   }

   creds.client = user_principal;

   /* Get the user's realm for building service principal */
   user_realm = krb5_princ_realm (kcontext, user_principal);
   
   /*
    * Build the service name into a principal. Right now this is
    * a TGT for the user's realm.
    */
   code = krb5_build_principal_ext (kcontext,
               &service_principal,
               user_realm->length,
               user_realm->data,
               tgtname.length,
               tgtname.data,
               user_realm->length,
               user_realm->data,
               0 /* terminator */);
   
   if (code) {
       com_err (my_name, code, "building service principal name");
       goto cleanup;
   }

   creds.server = service_principal;

   creds.times.starttime = 0;   /* Now */
   creds.times.endtime = now + lifetime;
   creds.times.renew_till = 0;   /* Unrenewable */

   /* DO IT */
   code = krb5_get_in_tkt_with_password (kcontext,
               options,
               addrs,
               NULL,
               preauth,
               password,
               0,
               &creds,
               0);
   
   /* We are done with password at this point... */

   if (code) {   
      /* FAILURE - Parse a few common errors here */
      switch (code) {
      case KRB5KRB_AP_ERR_BAD_INTEGRITY:
         com_err (my_name, 0, "Bad password for %.100s", principal_name);
         break;

      case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
         com_err (my_name, 0, "Unknown user \"%.100s\"", principal_name);
         break;

      default:
         com_err (my_name, code, "checking Kerberos password for %.100s",
                  principal_name);
         }

      result = 0;
   } else {
      /* SUCCESS */
      result = 1;
   }
   
   /* Cleanup */
   cleanup:
      krb5_free_cred_contents (kcontext, &creds);

   return result;
}


void chomp (char *buf) {
   int i;
   int j = strlen (buf);
   for (i = 0; i < j; i++) {
      if (buf[i] == '\r' || buf[i] == '\n') {
         buf[i] = '\0';
         return;
      }
   }
}

int main (int argc, char *argv[]) {
   char uname[MAX_BUF], passwd[MAX_BUF], buf[MAX_BUF];

   /* Retrieve the username and passwd from stdin */
   uname[0] = passwd[0] = '\0';
   buf[sizeof(buf) - 1] = '\0';
   while (fgets (buf, sizeof(buf) - 1, stdin) != NULL) {
      chomp (buf);
      if (strncmp (buf, NAMESTR, strlen(NAMESTR)) == 0) {
         strcpy (uname, buf + sizeof(NAMESTR) - 1);
      }
      if (strncmp (buf, PASSSTR, strlen(PASSSTR)) == 0) {
         strcpy (passwd, buf + sizeof(PASSSTR) - 1);
      }
   }

   /*
      Must have a username/password, and no '@' in the address.
      @ checking is there to prevent authentication against another
      Kerberos realm; there should be a --realm= commandline option
      to make this check unnecessary in the future.
   */

   if (!uname[0] || !passwd[0] || strrchr(uname, '@')) exit (3);

   /* Need to append instance name, passed as --instance=blah */
   if (argc - 1) {
      if (strncmp (argv[1], INSTANCE, strlen(INSTANCE)) == 0) {
         strncat (uname, "/", 1);
         strncat (uname, argv[1] + sizeof(INSTANCE) - 1, MAX_BUF - 
                  strlen(uname) - strlen(argv[1] + sizeof(INSTANCE) - 1)); 
      } else {
         fprintf (stderr, "Error parsing commandline options\n");
         exit (1);
      }
   }

   if (krb5_check_password(uname, passwd)) {
      fprintf (stdout, "User:%s\n", uname);
      return (0);
   } else {
      fprintf (stderr, "Failure validating password\n");
      exit (1);
   }
}
