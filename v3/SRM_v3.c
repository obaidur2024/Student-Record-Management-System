// Student Record Management System
// Developer: Obaidur Rahman
// College: Jamia Millia Islamia, New Delhi
// Language: C
// Version : 3.0 (Account gate + AES-256 data encryption + PBKDF2 key derivation)


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define MAX_STUDENTS 500
#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 16
#define PBKDF2_ITERATIONS 100000
#define MAX_ATTEMPTS 3
#define LOCKOUT_SECONDS 30

    typedef struct student {

    char name[50];
    int roll;
    int class;
    char section;
    float mark;
    }S;

    //global in-memory storage
    S students[MAX_STUDENTS];
    int student_count = 0;
    unsigned char data_key[KEY_LEN];
    unsigned char data_salt[SALT_LEN];
    char current_password[65] = {0};

    //hashing (Part 1, unchanged)
    void hash_password(const char *input, char *output){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)input, strlen(input), hash);

        for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
            sprintf(output + (i*2), "%02x", hash[i]);
        }
        output[64] = '\0';
    }

    //account gate
    int account_exists(void) {
        struct stat buffer;
        return (stat("password.dat", &buffer) == 0 && buffer.st_size > 0);
    }

    void first_time_setup(unsigned char *salt_out) {
        printf("\n--- FIRST-TIME SETUP ---\n");
        printf("No account found. Username is fixed as \"admin\".\n");

        char newpass[30], confirm[30];
        do {
            printf("Create new admin password : ");
            fgets(newpass, sizeof(newpass), stdin);
            newpass[strcspn(newpass, "\n")] = '\0';
            printf("Confirm password          : ");
            fgets(confirm, sizeof(confirm), stdin);
            confirm[strcspn(confirm, "\n")] = '\0';
            if (strcmp(newpass, confirm) != 0) {
                printf("Passwords do not match. Try again.\n");
            }
        } while (strcmp(newpass, confirm) != 0);

        // 1. save login hash
        char hashed[65];
        hash_password(newpass, hashed);
        FILE *pass = fopen("password.dat", "wb");
        if (pass == NULL) {
            printf("Error: Could not create password file.\n");
            exit(1);
        }
        fwrite(hashed, sizeof(hashed), 1, pass);
        fclose(pass);

        // 2. generate and save random salt for the data key
        RAND_bytes(salt_out, SALT_LEN);
        FILE *saltf = fopen("data.salt", "wb");
        if (saltf == NULL) {
            printf("Error: Could not create salt file.\n");
            exit(1);
        }
        fwrite(salt_out, SALT_LEN, 1, saltf);
        fclose(saltf);

        printf("Account created. Please log in.\n\n");
    }

    //PBKDF2 -> 32-byte AES-256 key
    void derive_data_key(const char *password, const unsigned char *salt, unsigned char *key_out) {
        PKCS5_PBKDF2_HMAC(password, -1, salt, SALT_LEN,
            PBKDF2_ITERATIONS, EVP_sha256(), KEY_LEN, key_out);
    }

    //portable cross-platform sleep (no <unistd.h> dependency)
    void sleep_seconds(int seconds) {
        time_t start = time(NULL);
        while (time(NULL) - start < seconds);
    }

    //encrypt plaintext buffer -> ciphertext (caller allocates ciphertext)
    int encrypt_buffer(const unsigned char *plaintext, int plaintext_len,
        const unsigned char *key, const unsigned char *iv,
        unsigned char *ciphertext) {

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            printf("Error: Failed to create cipher context.\n");
            return -1;
        }

        int len, ciphertext_len;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext_len;
    }

    //decrypt ciphertext -> plaintext. Returns -1 on bad key / corruption.
    int decrypt_buffer(const unsigned char *ciphertext, int ciphertext_len,
        const unsigned char *key, const unsigned char *iv,
        unsigned char *plaintext) {

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            return -1;
        }

        int len, plaintext_len;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
        plaintext_len = len;
        int final_ok = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        if (final_ok != 1) {
            return -1;   // wrong key or corrupted file
        }
        return plaintext_len;
    }

    //save_all_students -> encrypt in-memory array, write [IV | ciphertext] to data.enc
    int save_all_students(void) {

        //empty store -> just remove the file, fresh start on next load
        if (student_count == 0) {
            remove("data.enc");
            return 1;
        }

        unsigned char iv[IV_LEN];
        RAND_bytes(iv, IV_LEN);

        int plaintext_len = student_count * sizeof(S);
        unsigned char *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
        if (ciphertext == NULL) {
            printf("Error: Out of memory while saving.\n");
            return 0;
        }

        int ct_len = encrypt_buffer((unsigned char *)students, plaintext_len,
            data_key, iv, ciphertext);
        if (ct_len < 0) {
            free(ciphertext);
            return 0;
        }

        //backup-before-save (Section 11 of Part 3)
        remove("data.enc.bak");
        rename("data.enc", "data.enc.bak");

        FILE *f = fopen("data.enc", "wb");
        if (f == NULL) {
            printf("Error: Could not open data.enc for writing.\n");
            free(ciphertext);
            return 0;
        }
        fwrite(iv, IV_LEN, 1, f);
        fwrite(ciphertext, ct_len, 1, f);
        fclose(f);

        free(ciphertext);
        return 1;
    }

    //load_all_students -> read data.enc, decrypt into in-memory array
    int load_all_students(void) {

        FILE *f = fopen("data.enc", "rb");
        if (f == NULL) {
            //no data file yet -> first run after account creation
            student_count = 0;
            return 1;
        }

        unsigned char iv[IV_LEN];
        if (fread(iv, IV_LEN, 1, f) != 1) {
            fclose(f);
            student_count = 0;
            return 1;
        }

        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        long ct_len = file_size - IV_LEN;
        fseek(f, IV_LEN, SEEK_SET);

        if (ct_len <= 0) {
            fclose(f);
            student_count = 0;
            return 1;
        }

        unsigned char *ciphertext = malloc(ct_len);
        unsigned char *plaintext  = malloc(ct_len + AES_BLOCK_SIZE);
        if (ciphertext == NULL || plaintext == NULL) {
            fclose(f);
            free(ciphertext);
            free(plaintext);
            return 0;
        }

        fread(ciphertext, ct_len, 1, f);
        fclose(f);

        int pt_len = decrypt_buffer(ciphertext, ct_len, data_key, iv, plaintext);
        if (pt_len < 0) {
            free(ciphertext);
            free(plaintext);
            return 0;
        }

        student_count = pt_len / sizeof(S);
        if (student_count > MAX_STUDENTS) {
            student_count = MAX_STUDENTS;   //truncate on oversized file
        }
        memcpy(students, plaintext, student_count * sizeof(S));

        free(ciphertext);
        free(plaintext);
        return 1;
    }

    //check duplicate roll
    int roll_exists(int r) {
        for (int i = 0; i < student_count; i++) {
            if (students[i].roll == r) {
                return 1;
            }
        }
        return 0;
    }

    void addstudent(){
        S s1;
        if (student_count >= MAX_STUDENTS) {
            printf("Storage full. Cannot add more students.\n");
            return;
        }

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
        if (roll_exists(s1.roll)) {
            printf("Roll %d already exists.\n", s1.roll);
            return;
        }

        students[student_count++] = s1;
        if (save_all_students()) {
            printf("Student added successfully.\n");
        } else {
            student_count--;
            printf("Error: Failed to save record.\n");
        }
    }

    void showall (){
        if (student_count == 0) {
            printf("-NO DATA FOUND-");
            return;
        }
        for (int i = 0; i < student_count; i++) {
            printf("\nName    : %s", students[i].name);
            printf("Roll    : %d\n", students[i].roll);
            printf("Class   : %d\n", students[i].class);
            printf("Section : %c\n", students[i].section);
            printf("Marks   : %.2f\n", students[i].mark);
            printf("--------------------\n");
        }
    }

    //helper: edit one record (no duplicate check across roll)
    void edit_record(int idx) {
        S sx;

        getchar();
        printf("Name    : ");
        fgets(sx.name, sizeof(sx.name),stdin);
        printf("\nRoll    : ");
        scanf("%d",&sx.roll);
        printf("\nClass   : ");
        scanf("%d",&sx.class);
        getchar();
        printf("\nSection : ");
        sx.section = getchar();
        printf("\nMarks   : ");
        scanf("%f",&sx.mark);

        if (sx.mark < 0 || sx.mark > 100) {
            printf("Invalid marks. Enter a value between 0 and 100.\n");
            return;
        }

        students[idx] = sx;
        if (save_all_students()) {
            printf("Student updated successfully.\n");
        } else {
            printf("Error: Failed to save changes.\n");
        }
    }

    void searchstudent(int r){
        int idx = -1;
        for (int i = 0; i < student_count; i++) {
            if (students[i].roll == r) {
                idx = i;
                break;
            }
        }

        if (idx == -1) {
            printf("Roll not matched with any student ");
            return;
        }

        printf("\nName    : %s", students[idx].name);
        printf("Roll    : %d\n", students[idx].roll);
        printf("Class   : %d\n", students[idx].class);
        printf("Section : %c\n", students[idx].section);
        printf("Marks   : %.2f\n", students[idx].mark);

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

        if (ss == 1)
        {
            printf("\nEnter New Data");
            edit_record(idx);
        }

        else if (ss == 2)
        {
            //shift array left to fill the gap
            for (int i = idx; i < student_count - 1; i++) {
                students[i] = students[i+1];
            }
            student_count--;
            if (save_all_students()) {
                printf("Student deleted.");
            } else {
                printf("Error: Failed to save after delete.\n");
            }
        }

        else {
            printf("program exited");
        }
    }

    //CSV export (decrypted, on-demand only)
    void export_csv(void) {
        if (student_count == 0) {
            printf("No records to export.\n");
            return;
        }
        FILE *f = fopen("students_export.csv", "w");
        if (f == NULL) {
            printf("Error: Could not create CSV file.\n");
            return;
        }
        fprintf(f, "Name,Roll,Class,Section,Marks\n");
        for (int i = 0; i < student_count; i++) {
            char clean_name[50];
            strncpy(clean_name, students[i].name, sizeof(clean_name));
            clean_name[strcspn(clean_name, "\n")] = '\0';
            fprintf(f, "%s,%d,%d,%c,%.2f\n",
                clean_name, students[i].roll, students[i].class,
                students[i].section, students[i].mark);
        }
        fclose(f);
        printf("Exported to students_export.csv\n");
    }

    //change password -> also re-encrypt data with new key
    void change_password(void) {
        getchar();
        printf("Enter the new password : ");
        char newpass[30];
        fgets(newpass, sizeof(newpass), stdin);
        newpass[strcspn(newpass, "\n")] = '\0';

        char newhash[65];
        hash_password(newpass, newhash);

        FILE *pass = fopen("password.dat", "wb");
        if (pass == NULL) {
            printf("Error: Could not open password file.\n");
            return;
        }
        fwrite(newhash, sizeof(newhash), 1, pass);
        fclose(pass);

        //re-encrypt data file with the NEW key (so the new password works on next login)
        unsigned char new_key[KEY_LEN];
        derive_data_key(newpass, data_salt, new_key);
        memcpy(data_key, new_key, KEY_LEN);
        memset(new_key, 0, KEY_LEN);

        strncpy(current_password, newpass, sizeof(current_password) - 1);

        if (save_all_students()) {
            printf("Password changed successfully. Data re-encrypted with new key.\n");
        } else {
            printf("Password changed, but failed to re-encrypt data. Next login may fail.\n");
        }

        memset(newpass, 0, sizeof(newpass));
    }

int main (){

    //account gate
    if (!account_exists()) {
        first_time_setup(data_salt);
    } else {
        FILE *saltf = fopen("data.salt", "rb");
        if (saltf == NULL) {
            //upgrade path: v2 had password.dat but no salt. Generate one without
            //touching the existing password hash.
            RAND_bytes(data_salt, SALT_LEN);
            saltf = fopen("data.salt", "wb");
            if (saltf == NULL) {
                printf("Error: Could not create salt file.\n");
                return 1;
            }
            fwrite(data_salt, SALT_LEN, 1, saltf);
            fclose(saltf);
        } else {
            fread(data_salt, SALT_LEN, 1, saltf);
            fclose(saltf);
        }
    }

    //login with lockout
    printf("Sign in to your Account \n");
    int attempt = 0;
    int logged_in = 0;

    while (!logged_in) {

        char UserID[20]="admin";
        char checkUserID[20];
        printf("User ID :");
        fgets(checkUserID, sizeof(checkUserID), stdin);
        checkUserID[strcspn(checkUserID,"\n")]='\0';

        FILE *pass = fopen("password.dat", "rb");
        if (pass == NULL) {
            printf("Error: Could not open password file.\n");
            return 1;
        }
        char password[65];
        fread(password, sizeof(password), 1, pass);
        fclose(pass);

        char checkpassword[30];
        printf("Password :");
        fgets(checkpassword, sizeof(checkpassword), stdin);
        checkpassword[strcspn(checkpassword, "\n")] = '\0';

        char checkhash[65];
        hash_password(checkpassword, checkhash);

        if (strcmp(checkUserID, UserID) != 0 ||
            strcmp(checkhash, password) != 0) {
            printf("\nThe username or password you entered is incorrect \n \n");
            attempt++;
            if (attempt >= MAX_ATTEMPTS) {
                printf("Too many failed attempts. Locked out for %d seconds...\n", LOCKOUT_SECONDS);
                sleep_seconds(LOCKOUT_SECONDS);
                printf("Lockout ended. You may try again.\n\n");
                attempt = 0;
            }
        }
        else {
            printf("\nLogin successful \n");
            logged_in = 1;
            strncpy(current_password, checkpassword, sizeof(current_password) - 1);
            current_password[sizeof(current_password) - 1] = '\0';
        }

        memset(checkpassword, 0, sizeof(checkpassword));
        memset(checkhash, 0, sizeof(checkhash));
    }

    //derive AES key from the password that just authenticated us
    derive_data_key(current_password, data_salt, data_key);

    //load and decrypt student data
    if (!load_all_students()) {
        printf("Decryption failed - data may be corrupted or password incorrect.\n");
        memset(current_password, 0, sizeof(current_password));
        return 1;
    }

    //main menu loop
    while(1){
        printf("\n========================================\n");
        printf("Total students: %d\n", student_count);
        printf("========================================\n");
        printf("Please select an action from the menu below \n");
        printf("0 -> Information & Help \n");
        printf("1 -> Enter New Student \n");
        printf("2 -> Display All Records \n");
        printf("3 -> Find Student \n");
        printf("4 -> Manage password \n");
        printf("5 -> Export to CSV \n");
        printf("6 -> EXIT \n \n");

        printf("type number between 0 to 6 for action : ");
        int ac;
        scanf("%d",&ac);

        if (ac==1){
           addstudent();
        }
        else if (ac==2){
            showall();
        }
        else if (ac==3){
            printf("Enter the student roll number : ");
            int sr;
            scanf("%d",&sr);
            searchstudent(sr);
        }
        else if (ac==4){
            change_password();
        }
        else if (ac==5){
            export_csv();
        }

        else if (ac==0) {
                printf("\n========================================\n");
                printf("   STUDENT RECORD MANAGEMENT SYSTEM v3\n");
                printf("========================================\n");
                printf("Developer : Obaidur Rahman\n");
                printf("College   : Jamia Millia Islamia, New Delhi\n");
                printf("Purpose   : Built as a 1st year project to\n");
                printf("            practice C file handling and structs\n");
                printf("\n--- HOW TO USE ---\n");
                printf("1 -> Add a new student record\n");
                printf("2 -> Display all stored records\n");
                printf("3 -> Find a student by roll number\n");
                printf("     (also lets you edit or delete)\n");
                printf("4 -> Change the login password\n");
                printf("5 -> Export records to CSV\n");
                printf("6 -> Exit the program\n");
                printf("\n--- SECURITY NOTES (v3) ---\n");
                printf("- Login password is SHA-256 hashed (Part 1)\n");
                printf("- Student data file is AES-256-CBC encrypted\n");
                printf("- Data encryption key is derived from the\n");
                printf("  password using PBKDF2 (100000 iterations)\n");
                printf("  and is never written to disk\n");
                printf("- Salt stored in data.salt, IV in data.enc\n");
                printf("  - both are public, only the password is secret\n");
                printf("- %d failed logins trigger a %d-second lockout\n",
                    MAX_ATTEMPTS, LOCKOUT_SECONDS);
                printf("- Auto backup of previous data.enc kept as\n");
                printf("  data.enc.bak before every save\n");
                printf("\n--- TECHNICAL NOTES (v3) ---\n");
                printf("- All records are held in memory as an array\n");
                printf("  and encrypted/decrypted as one block -\n");
                printf("  removes the v2 fseek edit/double-fclose bug\n");
                printf("- Forgot your password? The encrypted data is\n");
                printf("  unrecoverable by design. No backdoor exists.\n");
                printf("========================================\n");
        }

        else if (ac==6){
            printf("\nExiting... Goodbye!\n");
            break;
        }

        else {
            printf("Invalid input..!\n");
        }
    }

    memset(current_password, 0, sizeof(current_password));
    memset(data_key, 0, KEY_LEN);

    return 0;
}
