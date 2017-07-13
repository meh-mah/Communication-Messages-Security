/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.utils.Util;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;




/**
 *
 * @author M&M
 */
public class SSLClient {
    
    private SSLSocket socket;
    BufferedReader reader;
    ObjectOutputStream out;
    
    private final String DEFULT_ALIAS="bob";
    private String alias=DEFULT_ALIAS;
   
    private final int DEFAULT_PORT=49152;
    private final String DEFAULT_HOST="localhost";
   
    private String host=DEFAULT_HOST;
    private int port=DEFAULT_PORT;
   
    private final String DEFAULT_KEYSTORE="clientKeys";
    private final String DEFAULT_KEYSTORE_PASSWORD="123456";
    private String keyStore=DEFAULT_KEYSTORE;
    private String keyStorePassword=DEFAULT_KEYSTORE_PASSWORD;
   
    private final String DEFAULT_TRUSTSTORE="clientTrust";
    private final String DEFAULT_TRUSTSTORE_PASSWORD="123456";
    private String trustStore=DEFAULT_TRUSTSTORE;
    private String trustStorePassword=DEFAULT_TRUSTSTORE_PASSWORD;
    
    private int currentUserId;
    private ClientUI ui;
    
    private boolean connected=false;
    

    public SSLClient(ClientUI ui, String[] args) {
        this.ui = ui;

        // Parse the command-line
    boolean parseFailed=false;
    int i=0;
    while (i<args.length && !parseFailed) {
      // We pass, to handleCommandLineOption, the entire array
      // of arguments and the position of the cursor.
      // It returns the number of successfully handled arguments,
      // or zero if an error was encountered.
      int handled=handleCommandLineOption(args, i);
      if (handled==0) parseFailed=true;
      else i+=handled;
    }
    
    if (parseFailed) {
      // Something went wrong with the command-line parse.
      // A real application would issue a good error message;
      // we'll just display our usage.
      displayUsage();
    }
    }
    
      private int handleCommandLineOption(String[] args, int i)
  {
    int res;
    try {
      String arg=args[i].trim().toUpperCase();
        switch (arg) {
            case "-PORT":
                port=Integer.parseInt(args[i+1]);
                res=2;
                break;
            case "-HOST":
                host=args[i+1];
                res=2;
                break;
            case "-KS":
                keyStore=args[i+1];
                res=2;
                break;
            case "-KSPASS":
                keyStorePassword=args[i+1];
                res=2;
                break;
            case "-TS":
                trustStore=args[i+1];
                res=2;
                break;
            case "-TSPASS":
                trustStorePassword=args[i+1];
                res=2;
                break;
            case "-ALIAS":
                alias=args[i+1];
                res=2;
                break;
            default:
                res=0;
                break;
        }
    }
    catch(Exception e) {
      // Something went wrong with the command-line parse.
      res=0;
    }

    return res;
  }

  /**
   * Displays the command-line usage for this client.
   */
  private void displayUsage()
  {
    System.out.println("Options:");
    System.out.println("\t-host\thost of server (default '"+DEFAULT_HOST+"')");
    System.out.println("\t-port\tport of server (default "+DEFAULT_PORT+")");
    System.out.println("\t-ks\tkeystore (default '"
                       +DEFAULT_KEYSTORE+"', JKS format)");
    System.out.println("\t-kspass\tkeystore password (default '"
                       +DEFAULT_KEYSTORE_PASSWORD+"')");
    System.out.println("\t-ts\ttruststore (default '"
                       +DEFAULT_TRUSTSTORE+"', JKS format)");
    System.out.println("\t-tspass\ttruststore password (default '"
                       +DEFAULT_TRUSTSTORE_PASSWORD+"')");
    System.out.println("\t-alias\talias to use");
  }

  /**
   * Provides a SSLSocketFactory which ignores JSSE's choice of keystore,
   * and instead uses either the hard-coded filename and password, or those
   * passed in on the command-line.
   * This method calls out to getKeyManagers() to do most of the
   * grunt-work. It actally just needs to set up a SSLContext and obtain
   * the SSLSocketFactory from there.
   */
  private SSLSocketFactory getSSLSocketFactory()
    throws IOException, GeneralSecurityException
  {
    // Call the superclasses to get suitable trust and key managers
    KeyManager[] kms=getKeyManagers();
    TrustManager[] tms=getTrustManagers();

    // If the alias has been specified, wrap recognised KeyManagers
    // in AliasChoosingKeyManager instances.
    if (alias!=null) {
      for (int i=0; i<kms.length; i++) {
        // We can only deal with instances of X509KeyManager
        if (kms[i] instanceof X509KeyManager)
          kms[i]=new AliasChoosingKeyManager((X509KeyManager)kms[i], alias);
      }
    }

    // Now construct a SSLContext using these
    // KeyManagers, and the TrustManagers. We still use a null
    // SecureRandom, indicating that the defaults should be used.
    SSLContext context=SSLContext.getInstance("SSL");
    context.init(kms, tms, null);

    // Finally, we get a SocketFactory
    SSLSocketFactory ssf=context.getSocketFactory();
    return ssf;
  }

  /**
   * Returns an array of KeyManagers, set up to use the required
   * keyStore. This is pulled out separately so that later  
   * examples can call it.
   * This method does the bulk of the work of setting up the custom
   * trust managers.
   */
  private KeyManager[] getKeyManagers()
    throws IOException, GeneralSecurityException
  {
    // First, get the default KeyManagerFactory.
    String alg=KeyManagerFactory.getDefaultAlgorithm();
    KeyManagerFactory kmFact=KeyManagerFactory.getInstance(alg);
        KeyStore ks;
        try (FileInputStream fis = new FileInputStream(keyStore)) {
            ks = KeyStore.getInstance("jks");
            ks.load(fis, keyStorePassword.toCharArray());
        }

    // Now we initialise the KeyManagerFactory with this KeyStore
    kmFact.init(ks, keyStorePassword.toCharArray());

    // And now get the KeyManagers
    KeyManager[] kms=kmFact.getKeyManagers();
    return kms;
  }
  
   /**
   * Returns an array of TrustManagers, set up to use the required
   * trustStore. This is pulled out separately so that later  
   * examples can call it.
   * This method does the bulk of the work of setting up the custom
   * trust managers.
   */
  protected TrustManager[] getTrustManagers()
    throws IOException, GeneralSecurityException
  {
    // First, get the default TrustManagerFactory.
    String alg=TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmFact=TrustManagerFactory.getInstance(alg);
        KeyStore ks;
        try (FileInputStream fis = new FileInputStream(trustStore)) {
            ks = KeyStore.getInstance("jks");
            ks.load(fis, trustStorePassword.toCharArray());
        }

    // Now we initialise the TrustManagerFactory with this KeyStore
    tmFact.init(ks);

    // And now get the TrustManagers
    TrustManager[] tms=tmFact.getTrustManagers();
    return tms;
  }
  
  /**
   * Connects to the server, using the supplied SSLSocketFactory.
   * Returns only after the SSL handshake has been completed.
   */
  private void connect(SSLSocketFactory sf) throws IOException
  {
    socket=(SSLSocket)sf.createSocket(host, port);

    try {
        socket.startHandshake();
        InputStream is=socket.getInputStream();
        OutputStream os = socket.getOutputStream();
        out = new ObjectOutputStream(os);
        
        // Set up a reader to the socket. We use UTF-8 to represent text; this
        // matches the server. The JVM really should support UTF-8 - if it
        // doesn't we'll fall back to the JVM's default codepage.
        try {
            reader=new BufferedReader(new InputStreamReader(is, "UTF-8"));       
        } catch (UnsupportedEncodingException uee) {
            System.out.println("Warning: JVM cannot support UTF-8. Using default instead");
            reader=new BufferedReader(new InputStreamReader(is));
        }
        
    }
    catch (IOException ioe) {
      // The handshake failed. Close the socket.
      try {
        socket.close();
      }
      catch (IOException ioe2) {
        // Ignore this; throw on the original error.
      }
      socket=null;
      throw ioe;
    }
  }


  /**
   * Disconnects from the server.
   */
  public void close()
  {

      if (socket!=null) try {
          socket.close();
      } catch (IOException ex) {
          Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
      }

    socket=null;
  }

    public String register(String userName, String pwd) {
        String response = null;
        try {
            if(!connected){
                // The command-line parse succeeded. Now connect using the
                // correct SSLSocketFactory.
                SSLSocketFactory ssf=getSSLSocketFactory();
                connect(ssf);
                System.out.println("Connected");
                connected=true;
            }
            byte[] signed_msg = signData("register,"+userName+","+pwd);
            byte[] encrypted_msg= encryptData(signed_msg);
              
            out.writeObject(encrypted_msg);;
            out.flush();
            
            response=reader.readLine();

        } catch (IOException | GeneralSecurityException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return response;

    }


    public String login(String userName, String pwd) {
        
      try {
          if (!connected){
        // The command-line parse succeeded. Now connect using the
        // correct SSLSocketFactory.
        SSLSocketFactory ssf=getSSLSocketFactory();
        connect(ssf);
        System.out.println("Connected");
        connected=true;
          }
        
      }
      catch (IOException | java.security.GeneralSecurityException ioe) {
        // Connect failed.
        System.out.println("Connection failed: "+ioe);
      }        
        String response = null;
        try {
               byte[] signed_msg = signData("login,"+userName+","+pwd);
               byte[] encrypted_msg= encryptData(signed_msg);
              
            out.writeObject(encrypted_msg);
            out.flush();
            
            response=reader.readLine(); 
            switch (response) {
                case "logged":
                    this.currentUserId=Integer.parseInt(reader.readLine());
                    ui.updateAfterLogin(userName);
                    break;
                case "al":
                    this.currentUserId=Integer.parseInt(reader.readLine());
                    ui.updateAfterLogin(userName);
                    break;
                
            }
        } catch (IOException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return response;
    }

    public void logout() {
        
        try {
            byte[] signed_msg = signData("Logout");
            byte[] encrypted_msg= encryptData(signed_msg);
            out.writeObject(encrypted_msg);
            out.flush();
        } catch (IOException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
            
       ui.updateAfterLogout();
       close();
    }
    
    public void send(String msg){

        try { 
            byte[] signed_msg = signData(msg);
            byte[] encrypted_msg= encryptData(signed_msg);
            out.writeObject(encrypted_msg);
            out.flush();
        } catch (IOException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }

    private byte[] signData(String msg1) {
        byte[] encoding = null;

        try {
            //Load the keystore
            byte[] msg=msg1.getBytes();
            PrivateKey pkey = null;
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fileinputstream = new FileInputStream(keyStore);
            ks.load(fileinputstream, keyStorePassword.toCharArray());
            
            //Get the certificate chain for the user, his certificate is the first in the chain
            X509Certificate[] certChain = Util.convertCertificateChain(ks.getCertificateChain(alias));
            X509Certificate cert = certChain[0];
            
            //export the private key
            Key key = ks.getKey(alias, keyStorePassword.toCharArray());
            if (key instanceof PrivateKey) {
                pkey = (PrivateKey) key;
            }
            
            SignedData sd = new SignedData(msg, SignedData.IMPLICIT);
            //It will include the certificate chain for verification
            sd.setCertificates((iaik.x509.X509Certificate[]) (X509Certificate[]) certChain);
            IssuerAndSerialNumber iS = new IssuerAndSerialNumber(cert);
            //create a new signer info object
            SignerInfo sI = new SignerInfo(iS, AlgorithmID.sha1, pkey);
            //add the signer information to the signed data
            sd.addSignerInfo(sI);
            // Prepare the SignedData object for transmission by immediately DER encoding it.
            encoding = sd.getEncoded();
        }
        catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | PKCSException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SSLClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return encoding;
    }
    
    private byte[] encryptData(byte[] signedData) throws Exception {
        
        byte[] encoded;
        
        // initialise "BC" provider
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks2 = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(trustStore);
        ks2.load(fis, trustStorePassword.toCharArray());
        X509Certificate cert = (X509Certificate) ks2.getCertificate("server");
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fileinputstream = new FileInputStream(keyStore);
        ks.load(fileinputstream, keyStorePassword.toCharArray());
        
        //Create enveloped data
        CMSTypedData ctd = new CMSProcessableByteArray(signedData);
        CMSEnvelopedDataGenerator edg = new CMSEnvelopedDataGenerator();
        edg.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
        CMSEnvelopedData ed = edg.generate(ctd, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build());
        encoded=ed.getEncoded();
        return encoded;
    }
}