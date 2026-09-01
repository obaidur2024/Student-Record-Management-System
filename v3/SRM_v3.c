// Student Record Management System
// Developer: Obaidur Rahman
// College: Jamia Millia Islamia, New Delhi
// Language: C
// Version : 3.0 (Account gate + Password-derived AES-256-CBC data encryption)
// Compile : gcc SRM_v3.c -o SRM -lssl -lcrypto


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 16
#define PBKDF2_ITERATIONS 100000
#define MAX_STUDENTS 100   //records now live in memory for the session, needs a cap

typedef struct student {

    char name[50];
    int roll;
    int class;
    char section;
    float mark;
    }S;

    typedef struct {
    char username_hash[65];
    char password_hash[65];
    }Credentials;

    //in-memory record store for the session
    S students[MAX_STUDENTS];
    int studentcount = 0;

    //hashing
    void hash_password(const char *input, char *output){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)input, strlen(input), hash);

        for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
            sprintf(output + (i*2), "%02x", hash[i]);
        }
        output[64] = '\0';
    }

    //check if an account has already been set up
    int account_exists(void){
        struct stat buffer;
        return (stat("password.dat",&buffer)==0 && buffer.st_size>0);
    }

    //first run - pick a username and password, hash both, make the data salt
    void first_time_setup(unsigned char *salt_out){
        printf("\n--- FIRST-TIME SETUP ---\n");
        printf("No account found. Let's create one.\n");

        char username[20];
        for (int i=0; i<1;) {
            printf("Choose a username :");
            fgets(username,sizeof(username),stdin);
            username[strcspn(username,"\n")]='\0';

            if (strlen(username)==0) {
                printf("Username cannot be empty.\n");
            }
            else {
                break;
            }
        }

        char newpass[30];
        char confirm[30];
        for (int i=0; i<1;) {
            printf("Create a password  :");
            fgets(newpass,sizeof(newpass),stdin);
            newpass[strcspn(newpass,"\n")]='\0';

            printf("Confirm password   :");
            fgets(confirm,sizeof(confirm),stdin);
            confirm[strcspn(confirm,"\n")]='\0';

            if (strcmp(newpass,confirm)!=0) {
                printf("Passwords do not match. Try again.\n");
            }
            else {
                break;
            }
        }

        Credentials cred;
        hash_password(username,cred.username_hash);
        hash_password(newpass,cred.password_hash);

        FILE *pass = fopen("password.dat","wb");
        if (pass==NULL) {
            printf("Error: Could not create password file.\n");
            return;
        }
        fwrite(&cred,sizeof(Credentials),1,pass);
        fclose(pass);

        RAND_bytes(salt_out,SALT_LEN);
        FILE *saltf = fopen("data.salt","wb");
        fwrite(salt_out,SALT_LEN,1,saltf);
        fclose(saltf);

        printf("Account created. Please log in.\n\n");
    }

    //turns the login password into a 32-byte AES key, never touches disk
    void derive_data_key(const char *password, const unsigned char *salt, unsigned char *key_out){
        PKCS5_PBKDF2_HMAC(password,-1,salt,SALT_LEN,PBKDF2_ITERATIONS,EVP_sha256(),KEY_LEN,key_out);
    }

    int encrypt_buffer(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext){
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len, ciphertext_len;

        EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv);
        EVP_EncryptUpdate(ctx,ciphertext,&len,plaintext,plaintext_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx,ciphertext+len,&len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext_len;
    }

    int decrypt_buffer(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext){
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len, plaintext_len;

        EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv);
        EVP_DecryptUpdate(ctx,plaintext,&len,ciphertext,ciphertext_len);
        plaintext_len = len;

        int ok = EVP_DecryptFinal_ex(ctx,plaintext+len,&len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        if (ok==0) {
            return -1;   //wrong key or corrupted file
        }
        return plaintext_len;
    }

    //reads data.enc (IV + ciphertext), decrypts it into the students array
    void load_all_students(unsigned char *key){
        studentcount = 0;

        FILE *f = fopen("data.enc","rb");
        if (f==NULL) {
            printf("No records found. File does not exist yet.\n");
            return;
        }

        unsigned char iv[IV_LEN];
        fread(iv,IV_LEN,1,f);

        fseek(f,0,SEEK_END);
        long ciphertext_len = ftell(f) - IV_LEN;
        fseek(f,IV_LEN,SEEK_SET);

        unsigned char *ciphertext = malloc(ciphertext_len);
        fread(ciphertext,ciphertext_len,1,f);
        fclose(f);

        unsigned char *plaintext = malloc(ciphertext_len + 16);
        int plaintext_len = decrypt_buffer(ciphertext,ciphertext_len,key,iv,plaintext);
        free(ciphertext);

        if (plaintext_len < 0) {
            printf("Decryption failed - data may be corrupted or password incorrect.\n");
            free(plaintext);
            return;
        }

        studentcount = plaintext_len / sizeof(S);
        memcpy(students,plaintext,plaintext_len);
        free(plaintext);
    }

    //encrypts the students array as one block and overwrites data.enc with a fresh IV
    void save_all_students(unsigned char *key){
        unsigned char iv[IV_LEN];
        RAND_bytes(iv,IV_LEN);

        int plaintext_len = studentcount * sizeof(S);
        unsigned char *ciphertext = malloc(plaintext_len + 16);
        int ciphertext_len = encrypt_buffer((unsigned char*)students,plaintext_len,key,iv,ciphertext);

        FILE *f = fopen("data.enc","wb");
        if (f==NULL) {
            printf("Error: Could not open data file for saving.\n");
            free(ciphertext);
            return;
        }

        fwrite(iv,IV_LEN,1,f);
        fwrite(ciphertext,ciphertext_len,1,f);
        fclose(f);
        free(ciphertext);
    }

    void addstudent(){
        if (studentcount >= MAX_STUDENTS) {
            printf("Student list is full.\n");
            return;
        }

        S s1;

        getchar();
        printf("Name    : ");
        fgets(s1.name, sizeof(s1.name),stdin);
        printf("\nRoll    : ");
        scanf("%d",&s1.roll);
        printf("\nClass   : ");
        scanf("%d",&s1.class);
        getchar();
        printf("\nSection : ");
        s1.section = getchar();
        printf("\nMarks   : ");
        scanf("%f",&s1.mark);

        if (s1.mark < 0 || s1.mark > 100) {
            printf("Invalid marks. Enter a value between 0 and 100.\n");
            return;
        }

        //check duplicate
        for (int i=0; i<studentcount; i++) {
            if (students[i].roll == s1.roll) {
                printf("Roll %d already exists.\n", s1.roll);
                return;
            }
        }

        students[studentcount] = s1;
        studentcount++;
        printf("Student added successfully.\n");
    }

   void showall (){
        int check=0;

        for (int i=0; i<studentcount; i++) {
            check=1;

            printf("\nName    : %s", students[i].name);
            printf("Roll    : %d\n", students[i].roll);
            printf("Class   : %d\n", students[i].class);
            printf("Section : %c\n", students[i].section);
            printf("Marks   : %.2f\n", students[i].mark);
            printf("--------------------\n");
        }
        if (check==0) {
            printf("-NO DATA FOUND-");
            }
    }

    void searchstudent(int r, unsigned char *key){
        int check=0;
        int loc=0;

        for (int i=0; i<studentcount; i++) {
            if (students[i].roll == r)
            {
                check =1;
                loc = i;
                printf("\nName    : %s", students[i].name);
                printf("Roll    : %d\n", students[i].roll);
                printf("Class   : %d\n", students[i].class);
                printf("Section : %c\n", students[i].section);
                printf("Marks   : %.2f\n", students[i].mark);
                break;
            }
        }
        if (check==0) {
            printf("Roll not matched with any student ");
            }
        if (check!=0)
        {

            printf("\nWhat do you want to do? \n1-Edit \n2-Delete \n3-Nothing \n");

            int ss;
            for (int i=0; i<1;) {
            printf("\nSelect only one 1/2/3 : ");
            scanf("%d",&ss);

            if (ss==1 || ss ==2 || ss == 3) {
                break;
                                 }

            else {
            printf("Wrong pick , Please select between 1 to 3");
                 }
            }

            if (ss ==1)
            {
                printf("\nEnter New Data");
                getchar();
                printf("Name    : ");
                fgets(students[loc].name, sizeof(students[loc].name),stdin);
                printf("\nRoll    : ");
                scanf("%d",&students[loc].roll);
                printf("\nClass   : ");
                scanf("%d",&students[loc].class);
                getchar();
                printf("\nSection : ");
                students[loc].section = getchar();
                printf("\nMarks   : ");
                scanf("%f",&students[loc].mark);

                if (students[loc].mark < 0 || students[loc].mark > 100) {
                    printf("Invalid marks. Enter a value between 0 and 100.\n");
                    return;
                }

                save_all_students(key);
            }

            else if (ss == 2)
            {
                for (int i=loc; i<studentcount-1; i++) {
                    students[i] = students[i+1];
                }
                studentcount--;

                save_all_students(key);

                printf("Student deleted.");
            }

            else {
            printf("program exited");
            }
        }
    }
int main (){

    unsigned char salt[SALT_LEN];

    if (!account_exists()) {
        first_time_setup(salt);
    }
    else {
        FILE *saltf = fopen("data.salt","rb");
        if (saltf==NULL) {
            printf("Error: salt file missing. Cannot decrypt data.\n");
            return 1;
        }
        fread(salt,SALT_LEN,1,saltf);
        fclose(saltf);
    }

    Credentials cred;
    FILE *pass = fopen("password.dat","rb");
    if (pass==NULL) {
        printf("Error: could not open password.dat\n");
        return 1;
    }
    fread(&cred,sizeof(Credentials),1,pass);
    fclose(pass);

    unsigned char data_key[KEY_LEN];

    //login
    printf("Sign in to your Account \n");
    for (int i=0; i<1;) {

        char username[20];
        char password[30];

        printf("Username :");
        fgets(username,sizeof(username),stdin);
        username[strcspn(username,"\n")]='\0';

        printf("Password :");
        fgets(password,sizeof(password),stdin);
        password[strcspn(password,"\n")]='\0';

        char userhash[65];
        char passhash[65];
        hash_password(username,userhash);
        hash_password(password,passhash);

        //check input
        if (strcmp(userhash, cred.username_hash) != 0 ||
            strcmp(passhash, cred.password_hash) != 0) {
            printf("\nThe username or password you entered is incorrect \n \n");
            i=0;
        }

        else { printf("\nLogin successful \n");
            derive_data_key(password, salt, data_key);
            i=1;
            }}

    load_all_students(data_key);

    //main menu loop
    while(1){
        printf("\nPlease select an action from the menu below \n");
        printf("0 -> Information & Help \n");
        printf("1 -> Enter New Student \n");
        printf("2 -> Display All Records \n");
        printf("3 -> Find Student \n");
        printf("4 -> Manage password \n");
        printf("5 -> EXIT \n \n");

        printf("type number between 0 to 5 for action : ");
        int ac;
        scanf("%d",&ac);

        if (ac==1){
           addstudent();
           save_all_students(data_key);
        }
        else if (ac==2){
            showall();
        }
        else if (ac==3){
            printf("Enter the student roll number : ");
            int sr;
            scanf("%d",&sr);
            searchstudent(sr, data_key);
        }
        else if (ac==4){
            getchar();
            printf("Enter the new password : ");
            char newpass[30];
            fgets(newpass,sizeof(newpass), stdin);
            newpass[strcspn(newpass, "\n")] = '\0';

            //data is keyed off the password, so a new password needs a re-encrypt with the new key
            unsigned char newkey[KEY_LEN];
            derive_data_key(newpass, salt, newkey);
            save_all_students(newkey);

            hash_password(newpass, cred.password_hash);

            FILE *passf = fopen("password.dat","wb");
            if (passf==NULL) {
                printf("Error: Could not open password file.\n");
            }
            else {
                fwrite(&cred, sizeof(Credentials), 1, passf);
                fclose(passf);
                memcpy(data_key, newkey, KEY_LEN);
                printf("Password changed successfully.\n");
            }
        }

        else if (ac==0) {
                printf("\n========================================\n");
                printf("   STUDENT RECORD MANAGEMENT SYSTEM\n");
                printf("========================================\n");
                printf("Developer : Obaidur Rahman\n");
                printf("College   : Jamia Millia Islamia, New Delhi\n");
                printf("Purpose   : Built as a project to practice\n");
                printf("            C file handling, structs and\n");
                printf("            basic applied cryptography\n");
                printf("\n--- HOW TO USE ---\n");
                printf("1 -> Add a new student record\n");
                printf("2 -> Display all stored records\n");
                printf("3 -> Find a student by roll number\n");
                printf("     (also lets you edit or delete)\n");
                printf("4 -> Change the login password\n");
                printf("5 -> Exit the program\n");
                printf("\n--- TECHNICAL NOTES (v3) ---\n");
                printf("- Username AND password are both hashed\n");
                printf("  with SHA-256, chosen at first-time setup\n");
                printf("- Student data lives in memory during the\n");
                printf("  session and is encrypted as one block\n");
                printf("  with AES-256-CBC before touching disk\n");
                printf("- The AES key is derived from your password\n");
                printf("  with PBKDF2 (100000 iterations) - it is\n");
                printf("  never written to disk, only kept in RAM\n");
                printf("- A fresh random IV is generated on every\n");
                printf("  save and stored as a header in data.enc\n");
                printf("- Forgetting the password means the data\n");
                printf("  cannot be recovered by anyone - by design\n");
                printf("- Every fopen is NULL-checked to avoid\n");
                printf("  crashes when a file is missing\n");
                printf("========================================\n");
        }

        else if (ac==5){
            save_all_students(data_key);
            printf("\nExiting... Goodbye!\n");
            break;
        }

        else {
            printf("Invalid input..!\n");
        }
    }

    return 0;
}
