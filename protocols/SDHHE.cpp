#define OPENSSL_API_COMPAT 0x10100000L
#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>
#include <cstdlib>
#include <fstream>
#include <chrono>

#include "../configs/config.h"
#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h" // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"
#include "openssl/sha.h"
using namespace std;
using namespace seal;


class CSP{

    public: 
    //Attributes
        PublicKey hePub;
        SecretKey hePriv;
        RelinKeys heRelin;
        GaloisKeys heGalois;
        stringstream relStream;
        RelinKeys analystRelKey;
        Ciphertext cipherUser;
        vector<Ciphertext> cprime;
        Ciphertext cres;
        Ciphertext F;
    //Methods

        CSP(shared_ptr<SEALContext> context2){
            cout << endl <<  "----------Constructor of CSP------------" << endl;
            this->generateRSAkeys();
            this->generateHEKeys(context2);
            cout << "-------Constructor of CSP finished------" << endl;
        }

        void generateRSAkeys(){
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;
            start = chrono::high_resolution_clock::now();
            int command1 = system("openssl genrsa -out cspPriv.pem 2048");
            int command2 = system("openssl rsa -in cspPriv.pem -outform PEM -pubout -out cspPub.pem");
            if (!(command1 && command2)){
                cout << "[+] openssl worked successfully" << endl;
            }
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(end-start);
            cout << "[+] RSA key pair is generated and each key is stored in a .pem file" << endl;
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
            
        }

        void processM1(SEALContext context, ifstream& file){

            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            start = chrono::high_resolution_clock::now();
            cout << "--- CSP is processing M1 ---" << endl;
            //find symmetric key
            int symmetricKeyCommand = system("openssl rsautl --decrypt -inkey cspPriv.pem -in analystSymKey.txt.enc > analystSymKey.txt.dec 2> /dev/null");
            if(!symmetricKeyCommand){
                cout << "[+] Message with symmetric key is decrypted successfully" << endl;
            }
            //-------------------

            //Extracting symkey from decrypted file
            ifstream symkeyfile("analystSymKey.txt.dec");
            string password;
            string myText;
            while (getline (symkeyfile, myText)) {
            // Output the text from the file
                password = myText;
            }
            symkeyfile.close();


            //Decrypt evk
            string command1 = "openssl enc -d -aes-256-cbc -in analystRelFile.txt.enc -out analystRelFile.txt.dec --pass pass:";
            string command2 = " 2> /dev/null";
            string commandFull = string(command1) + string(password) + string(command2);
            int evkDecCommand = system(commandFull.c_str());
            if(!evkDecCommand){
                cout << "[+] evk file has been decrypted successfully" << endl;
            }
            //-----------------

            //Read evk data into variable
            stringstream buffer;
            buffer << file.rdbuf();
            this->analystRelKey.unsafe_load(context, buffer);
            //-----------------
            end = chrono::high_resolution_clock::now();
            cout << "[+] evk from analyst has been stored successfully" << endl;
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "\t[?] Whole process took " << result.count() << " milliseconds" << endl;
            cout << "--- Done ---" << endl << endl;
        }

        void processM3(SEALContext context){

            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;
            start = chrono::high_resolution_clock::now();


        //Validating Hash
            int val = system("openssl dgst -verify analystPub.pem -keyform PEM -sha256 -signature hash.txt.sign -binary hash.txt");
            if(!val){
                cout << "[+] Signature is verified" << endl;
            }
        //----------------

        //Extracting symkey from decrypted file
            ifstream symkeyfile;
            symkeyfile.open("analystSymKey.txt.dec");
            string password;
            string myText;
            while (getline (symkeyfile, myText)) {
            // Output the text from the file
                password = myText;
            }
            symkeyfile.close();
        //-------------------------------------

        //Decrypt F function
            string command1 = "openssl enc -d -aes-256-cbc -in fFunction.txt.enc -out fFunction.txt.dec --pass pass:";
            string command2 = " 2> /dev/null";
            string commandFull = string(command1) + string(password);// + string(command2);
            int evkDecCommand = system(commandFull.c_str());
            if(!evkDecCommand){
                cout << "[+] evk file has been decrypted successfully" << endl;
            }
        //-----------------

        //Read evk data into variable
            ofstream file;
            file.open("fFunction.txt.dec");
            stringstream buffer;
            buffer << file.rdbuf();
            //this->F.unsafe_load(context, buffer);
            //-----------------
            end = chrono::high_resolution_clock::now();
            cout << "[+] F function has been stored successfully" << endl;
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
            file.close();
            cout << "--- Done ---" << endl << endl;
        //----------------------------

        }
        
        void processMessageFromUser(SEALContext context, ifstream& file, string userpass){
            
            //Encrypting the message
            string fullcommand = string("openssl enc -d -aes-256-cbc -in userFile.txt.enc -out userFile.txt.dec --pass pass:") + string(userpass) + string(" 2> /dev/null");
            int symmetricKeyCommand = system(fullcommand.c_str());
            if(!symmetricKeyCommand){
                cout << "[+] Message is decrypted successfully" << endl;
            }

            string line;
            stringstream buffer;
            buffer << file.rdbuf();
            //this->cipherUser.unsafe_load(context, buffer);
            cout << "[+] ciphertext is stored succesfully" << endl;
        }
        void generateHEKeys(shared_ptr<SEALContext> context){
            KeyGenerator cspKeygen(*context);
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            start = chrono::high_resolution_clock::now();
            this->hePriv = cspKeygen.secret_key();
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(start - end);
            cout << "[+] Secret HE key is generated" << endl;
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
        }

        void decompression(shared_ptr<SEALContext> context, PublicKey analystHePub, GaloisKeys gk, vector<Ciphertext> ck, vector<uint64_t> ci, RelinKeys sharedRelinKey){
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            start = chrono::high_resolution_clock::now();
            PASTA_3_MODIFIED_1::PASTA_SEAL worker(context, analystHePub, this->hePriv, sharedRelinKey, gk);
            this->cprime = worker.decomposition(ci, ck, config::USE_BATCH);
            //cout << "Size of Cprime : " << this->cprime.size() << endl;
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "[+] HHE.Decomp has been performed" << endl;
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
        }

        void evaluate(shared_ptr<SEALContext> context, Ciphertext f, PublicKey analystHePub){
            BatchEncoder analystHEBatch(*context);
            Encryptor analystHEEncryptor(*context, analystHePub);
            Evaluator analystHEEvaluator(*context);
            packed_enc_multiply(this->cprime[0], f, this->cres, analystHEEvaluator);
            cout << "[+] CSP has evaluated Cres" << endl;
            //packed_enc_addition(this->cres, Analyst.b_c, CSP.c_res, analystHEEvaluator);
        }
};

class Analyst{
    
    public: 
    //Attributes
        PublicKey hePub;
        SecretKey hePriv;
        RelinKeys heRelin;
        //Serializable<RelinKeys> heRelinSer;
        RelinKeys sharedHeRelin;
        stringstream relStream;
        size_t evkSize;
        GaloisKeys gk;
        vector<int64_t> f{17, 31, 24, 17, 32, 19};
        Ciphertext encF;
    //Methods

        Analyst(SEALContext context){
            cout << endl << "----------Constructor of Analyst------------" << endl;
            this->generateRSAkeys();
            this->generateHEKeys(context);
            cout << "-------Constructor of Analyst finished------" << endl;
        }

        void generateRSAkeys(){
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            start = chrono::high_resolution_clock::now();
            int command1 = system("openssl genrsa -out analystPriv.pem 2048");
            int command2 = system("openssl rsa -in analystPriv.pem -outform PEM -pubout -out analystPub.pem");
            if (!(command1 && command2)){
                cout << "[+] openssl worked successfully" << endl;
            }
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "[+] RSA key pair is generated and each key is stored in a .pem file" << endl;
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
        }

        void generateHEKeys(SEALContext context){
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            start = chrono::high_resolution_clock::now();
            shared_ptr<SEALContext> cc = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            KeyGenerator keygen(*cc);
            this->hePriv = keygen.secret_key(); // HE Decryption Secret Key
            keygen.create_public_key(this->hePub);
            keygen.create_relin_keys(this->sharedHeRelin);
            keygen.create_galois_keys(this->gk);
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "[+] HE keys and relin key are generated" << endl;
            cout << "\t[?] Took " << result.count() << " milliseconds" << endl;
        }


        Serializable<RelinKeys> getGenerateEVK(SEALContext context){
            KeyGenerator keygen(context);
            return keygen.create_relin_keys();
        }


        //Feeding relin key into buffer in order to be able to write the key into a file
        void generateAndWriteRelinStreamIntoFile(SEALContext context, ofstream& file){
            KeyGenerator keygen(context);
            auto evk = keygen.create_relin_keys();
            evk.save(file);
            cout << "[+] evk is generated and sent to the file stream" << endl;
        }
        
        //Creating Message1
        void createM1(SEALContext context, ofstream& file, ifstream& infile){
            cout << endl <<"---Creating M1---" << endl;
            chrono::high_resolution_clock::time_point creatingM1Start, creatingM1End;
            chrono::milliseconds delta;
            
            creatingM1Start = chrono::high_resolution_clock::now();

            //Extraction of the relinerization key
            auto relSize = this->heRelin.save(this->relStream);

            cout << "Size of evk : " << relSize << " bytes" << endl;
            this->evkSize = relSize;

            //Writing extracted rel key into a text file
            this->generateAndWriteRelinStreamIntoFile(context, file);

            //Getting key from a text file
            ifstream passwordFile("analystSymKey.txt");
            string password;
            string myText;
            while (getline (passwordFile, myText)) {
            // Output the text from the file
                password = myText;
            }
            passwordFile.close();
            
            //Constructing the command string for the signing operation
            string signCommandString = string("openssl enc -aes-256-cbc -in analystRelFile.txt -out analystRelFile.txt.enc --pass pass:") + string(password) + string(" 2> /dev/null");

            //signing evk with analyst signature
            int signCommand = system(signCommandString.c_str());
            if(!signCommand){
                cout << "[+] evk has been signed" << endl;
            }

            int encWithCSPpubkey = system("openssl rsautl -encrypt -inkey cspPub.pem -pubin -in analystSymKey.txt -out analystSymKey.txt.enc 2> /dev/null");
            if(!encWithCSPpubkey){
                cout << "[+] symmetric key has been encrypted with CSP public key" << endl;
            }
            creatingM1End = chrono::high_resolution_clock::now();
            delta = chrono::duration_cast<chrono::milliseconds>(creatingM1End - creatingM1Start);
            cout << "\t[?] Forging M1 took " << delta.count() << " milliseconds" << endl; 
            cout << "---Done---" << endl << endl;
        }

        void createM3(shared_ptr<SEALContext> cc, SEALContext context, ofstream& file, ifstream& infile){

            this->encryptF(cc);

        //Generating Encryption file with CSP public key------------
            this->encF.save(file); //Storing encrypted F result into file

            //int encWithCSPpubkey = system("openssl rsautl -encrypt -inkey cspPub.pem -pubin -in fFunction.txt -out fFunction.txt.enc");  //Dosya adını yaz 
            //Above line supposed to encrypt the f value with CSP public key. But it throws an error, saying the file is too big to encrypt. I am going to encrypt this one 
            //like I have encrypted evk key. 

            //Getting key from a text file
            ifstream passwordFile("analystSymKey.txt");
            string password;
            string myText;
            while (getline (passwordFile, myText)) {
            // Output the text from the file
                password = myText;
            }
            passwordFile.close();
            //Constructing the command string for the signing operation
            string signCommandString = string("openssl enc -aes-256-cbc -in analystRelFile.txt -out analystRelFile.txt.enc --pass pass:") + string(password) + string(" 2> /dev/null");
            //signing evk with analyst signature
            int signCommand = system(signCommandString.c_str());
            if(!signCommand){
                cout << "[+] F function is encrypted with CSP public key" << endl;
            }
        //------------------------------------------------------
            
            
        //Generating the hash value-----------------------------
            //initializing timestamp variable
            size_t timestamp;
            const auto now = std::chrono::system_clock::now();
            timestamp = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();  //Getting system time
            string timestampString = to_string(timestamp); //Data cast to string in order to be able to feed into buffer.

            //Reading evk key from file
            stringstream buffer;
            buffer << infile.rdbuf();
            string bufferToString = buffer.str();
            
            //Concat timestamp and evk
            string finalValue = bufferToString + timestampString;
            file << finalValue;

            //Hashing
            string echo = "echo '' > hash.txt";
            string comm = "echo -n hash.txt | sha256sum > hash.txt"; //Hash value is stored in a file.
            int command = system(comm.c_str());

            //Signing the file
            string sign = "openssl dgst -sign analystPriv.pem -keyform PEM -sha256 -out hash.txt.sign -binary hash.txt";
            int signComm = system(sign.c_str());
            if(!signComm){
                cout << "[+] Hash value has been signed" << endl;
            }

        //------------------------------------------------------
        }

        void encryptF(shared_ptr<SEALContext> context){
            chrono::high_resolution_clock::time_point start, end;
            chrono::milliseconds result;

            BatchEncoder analystHEBatch(*context);
            Encryptor analystHEEncryptor(*context, this->hePub);
            Evaluator analystHEEvaluator(*context);
            start = chrono::high_resolution_clock::now();
            this->encF = encrypting(this->f, this->hePub, analystHEBatch, analystHEEncryptor);
            end = chrono::high_resolution_clock::now();
            result = chrono::duration_cast<chrono::milliseconds>(end - start);
            cout << "[+] Analyst encrypted his input" << endl;
            cout << "\t[?] Encrypting took " << result.count() << " milliseconds" << endl;
        }

        void decryptCres(shared_ptr<SEALContext> context, Ciphertext cres){
            BatchEncoder analystHEBatch(*context);
            Encryptor analystHEEncryptor(*context, this->hePub);
            Evaluator analystHEEvaluator(*context);
            vector<int64_t> resDecrypted = decrypting(cres, this->hePriv, analystHEBatch, *context, this->f.size());
            cout << "Decrypted vector : " << endl;
            for (int i = 0; i < resDecrypted.size(); i++){
                cout << resDecrypted[i] << " ";
            }
            cout << endl;
            //print_vec(resDecrypted, resDecrypted.size(), "decrypted result");
        }

         
};

class User{

    public:
    //Attributes
        PublicKey hePub;
        SecretKey hePriv;
        RelinKeys heRelin;
        vector<uint64_t> plaintext;
        vector<uint64_t> ssk;
        vector<uint64_t> ci;
        vector<Ciphertext> ck;
        string pass;
    //Methods

        User(){
            cout << endl << "----------Constructor of User------------" << endl;
            chrono::high_resolution_clock::time_point rsaStart, rsaEnd, sskStart, sskEnd;
            chrono::milliseconds rsaRes, sskRes;

            rsaStart = chrono::high_resolution_clock::now();
            this->generateRSAkeys();
            rsaEnd = chrono::high_resolution_clock::now();
            rsaRes = chrono::duration_cast<chrono::milliseconds> (rsaEnd - rsaStart);
            cout << "\t[?] Took " << rsaRes.count() << " milliseconds" << endl;
            sskStart = chrono::high_resolution_clock::now();
            this->generateSSKkey();
            sskEnd = chrono::high_resolution_clock::now();
            sskRes = chrono::duration_cast<chrono::milliseconds>(sskEnd - sskStart);
            cout << "\t[?] Took " << sskRes.count() << " milliseconds" << endl;
            this->plaintext = {0,1,2,3,4,5};
            cout << "-------Constructor of User finished------" << endl;
        }

        void generateRSAkeys(){
            int command1 = system("openssl genrsa -out userPriv.pem 2048");
            int command2 = system("openssl rsa -in userPriv.pem -outform PEM -pubout -out userPub.pem");
            if (!(command1 && command2)){
                cout << "[+] openssl worked successfully" << endl;
            }
            cout << "[+] RSA key pair is generated and each key is stored in a .pem file" << endl;
        }

        void generateSSKkey(){
            this->ssk = get_symmetric_key();
            cout << "[+] ssk key is generated" << endl;
        }

        void encryptSSK(shared_ptr<SEALContext> context, PublicKey analystHePub, SecretKey he_sk, PublicKey he_pk, RelinKeys he_rk, GaloisKeys he_gk){ //Analyst context and public key
            this->generateSSKkey();
            BatchEncoder analystHEBatch(*context);
            Encryptor analystHEEncryptor(*context, analystHePub);
            Evaluator analystHEEvaluator(*context);
            PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(this->ssk, config::plain_mod);
            this->ci = SymmetricEncryptor.encrypt(this->plaintext);
            this->ck = encrypt_symmetric_key(this->ssk, config::USE_BATCH, analystHEBatch, analystHEEncryptor);  //only one data x
            cout << "[+] Encrypted SSK successfully" << endl;
        }


        void writeCKandCintoFile(ofstream& file){
            
            
            this->ck[0].save(file);  //Prepare it for multiple ci's
            // file << "\n";
            // for (unsigned int i = 0; i < this->ci.size(); i++){
            //     file << this->ci[i] << "/";
            // }
            cout << "[+] Stored ci and ck into a file" << endl;
        }

        void encryptCKCIFile(){
            ifstream passwordFile("userSymKey.txt");
            string password;
            string myText;
            while (getline (passwordFile, myText)) {
            // Output the text from the file
                password = myText;
            }
            passwordFile.close();
            this->pass = string(password);
            //Constructing the command string for the signing operation
            string signCommandString = string("openssl enc -aes-256-cbc -in userFile.txt -out userFile.txt.enc --pass pass:") + string(password) + string(" 2> /dev/null");

            //signing evk with analyst signature
            int signCommand = system(signCommandString.c_str());
            if(!signCommand){
                cout << "[+] evk has been signed" << endl;
            }
        }

        void sendMessageToCSP(shared_ptr<SEALContext> context, PublicKey analystHePub, ofstream& file, SecretKey he_sk, PublicKey he_pk, RelinKeys he_rk, GaloisKeys he_gk){
            chrono::high_resolution_clock::time_point sskStart, sskEnd, writeStart, writeEnd, encStart, encEnd;
            chrono::milliseconds ssk, write, enc;

            sskStart = chrono::high_resolution_clock::now();
            this->encryptSSK(context, analystHePub, he_sk, he_pk, he_rk, he_gk);
            sskEnd = chrono::high_resolution_clock::now();
            cout << "\t[?] Took " << chrono::duration_cast<chrono::milliseconds>(sskEnd - sskStart).count() << " milliseconds" << endl;

            writeStart = chrono::high_resolution_clock::now();
            this->writeCKandCintoFile(file);
            writeEnd = chrono::high_resolution_clock::now();
            cout << "\t[?] Took " << chrono::duration_cast<chrono::milliseconds>(writeEnd - writeStart).count() << " milliseconds" << endl;

            encStart = chrono::high_resolution_clock::now();
            this->encryptCKCIFile();
            encEnd = chrono::high_resolution_clock::now();
            cout << "\t[?] Took " << chrono::duration_cast<chrono::milliseconds>(encEnd - encStart).count() << " milliseconds" << endl;
        }

};


int main(void){

//Setting parameters
    //The reason that I am using two different context is, one context is for to be able to extract evk and ci's. Context2 is for evaluations and encryptions. 
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(config::mod_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(config::mod_degree, { 48, 48, 48, 49, 49, 49, 49, 49, 49 }));
    parms.set_plain_modulus(PlainModulus::Batching(config::mod_degree, 20));
    parms.set_plain_modulus(config::plain_mod);
    shared_ptr<SEALContext> context2 = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
//-----------------------------    

//Setting SEAL context
    SEALContext context(parms);
    print_parameters(context);
//-----------------------------  

    chrono::high_resolution_clock::time_point setupStart, setupEnd, addStart, addEnd, queryStart, queryEnd;
    chrono::milliseconds deltaSetup, deltaAdd, deltaQuery;

    cout << endl << endl << "-*-*-*-*-*-*SD.SETUP START-*-*-*-*-*-*" << endl;

//Construtcing classes--------
    CSP csp(context2);
    Analyst analyst(context);

    User us1;
//----------------------------

    setupStart = chrono::high_resolution_clock::now(); 
//Opening out stream file for the communication between CSP and User
    ofstream outFileUser;
    outFileUser.open("userFile.txt");
//-----------------------------

//Opening in stream file for the communication between CSP and User
    ifstream inFileUser;
    inFileUser.open("userFile.txt.dec");
//-----------------------------

//Constructing message 1------
    //Opening out stream file for the communication between CSP and Analyst
    ofstream outFile;
    outFile.open("analystRelFile.txt");
    ifstream relInFile;
    relInFile.open("analystRelFile.txt");
    ofstream hashOutFile;
    hashOutFile.open("hash.txt");
    ifstream hashInFile;
    hashInFile.open("hash.txt");
    analyst.createM1(context, outFile, relInFile);
//-----------------------------


//Opening in stream file for the communication between CSP and Analyst
    ifstream inFile;
    inFile.open("analystRelFile.txt.dec");

    csp.processM1(context, inFile);
//-----------------------------
    setupEnd = chrono::high_resolution_clock::now();
    cout << "-*-*-*-*-*-*SD.SETUP FINISHED-*-*-*-*-*-*" << endl;
    deltaSetup = chrono::duration_cast<chrono::milliseconds>(setupEnd - setupStart);
    cout << "SD.Setup total amount of time : " << deltaSetup.count() << " milliseconds"  << endl;



    cout << endl << endl << "-*-*-*-*-*-*SD.ADD START-*-*-*-*-*-*" << endl;
    addStart = chrono::high_resolution_clock::now();

//User send message to CSP-----
    cout << endl << "User Generating M2----" << endl;
    us1.sendMessageToCSP(context2, analyst.hePub, outFileUser, analyst.hePriv, analyst.hePub, analyst.heRelin, analyst.gk);
    cout << "--- Done ---" << endl;  //hesapla
//-----------------------------
    
//CSP operations---------------
    cout << endl << "CSP----" << endl;
    csp.processMessageFromUser(context, inFileUser, us1.pass);
    csp.decompression(context2, analyst.hePub, analyst.gk, us1.ck, us1.ci, analyst.sharedHeRelin);
    cout << "-----" << endl;
//-----------------------------


    addEnd = chrono::high_resolution_clock::now();
    cout << "-*-*-*-*-*-*SD.ADD FINISHED-*-*-*-*-*-*" << endl;
    deltaAdd = chrono::duration_cast<chrono::milliseconds>(addEnd - addStart);
    cout << "SD.Add total amount of time : " <<  deltaAdd.count() << " milliseconds" << endl;
    
    cout << endl << endl << "-*-*-*-*-*-*SD.Query START-*-*-*-*-*-*" << endl;
    queryStart = chrono::high_resolution_clock::now();

//Constructing Message 3----
    ofstream fFunction;
    fFunction.open("fFunction.txt");
    ifstream fFunctionIn;
    fFunctionIn.open("fFunction.txt");
    cout << "M3 being generated---" << endl;
    analyst.createM3(context2, context, fFunction, fFunctionIn);
    cout << "--- Done ---" << endl;
//---------------------------

//CSP operations-------------
    cout << "M3 being processed---" << endl;
    csp.processM3(context);
    csp.evaluate(context2, analyst.encF, analyst.hePub);
//---------------------------

//Analyst decrypt Res--------
    analyst.decryptCres(context2, csp.cres);
    queryEnd = chrono::high_resolution_clock::now();
//---------------------------
    cout << "-*-*-*-*-*-*SD.Query FINISHED-*-*-*-*-*-*" << endl;
    deltaQuery = chrono::duration_cast<chrono::milliseconds>(queryEnd - queryStart);
    cout << "SD.Query total amount of time : " <<  deltaQuery.count() << " milliseconds"  << endl;

    
    //int echo = system("echo '' | tee *.txt; echo '' | tee *.enc; echo '' | tee *.dec; echo '' | tee *.txt.dec; echo '' | tee *.txt.enc; echo '' | tee *.sign");
    return 0;
}