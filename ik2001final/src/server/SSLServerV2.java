package server;



import javax.net.ssl.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import exception.AlreadyLoggedInException;
import exception.RejectedException;
import iaik.asn1.ASN1Object;
import iaik.asn1.DerCoder;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.security.provider.IAIK;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * simple server which accepts SSL connections, and displays
 * text sent through the SSL socket on stdout. The server requires
 * client authentication.
 * Listens on port 49152 by default, configurable with "-port" on the
 * command-line.
 * The server needs to be stopped with Ctrl-C.
 */
public class SSLServerV2 extends Thread
{
  private final int DEFAULT_PORT=49152;

  private SSLServerSocketFactory serverSocketFactory;
  private int port=DEFAULT_PORT;
  private final String DEFAULT_TRUSTSTORE="serverTrust";
  private final String DEFAULT_TRUSTSTORE_PASSWORD="123456";

  private String trustStore=DEFAULT_TRUSTSTORE;
  private String trustStorePassword=DEFAULT_TRUSTSTORE_PASSWORD;
  
  private final String DEFAULT_KEYSTORE="serverKeys";
  private final String DEFAULT_KEYSTORE_PASSWORD="123456";

  private String keyStore=DEFAULT_KEYSTORE;
  private String keyStorePassword=DEFAULT_KEYSTORE_PASSWORD;
  
  
  public static void main(String args[])
  {
      SSLServerV2 server=new SSLServerV2(args);
      server.start();

  }
  /**
   * To handle the -ks  -kspass -ts -tspass -port and port arguments.
   */
  private int handleCommandLineOption(String[] args, int i)
  {
    int out;
    try {
      String arg=args[i].trim().toUpperCase();

        switch (arg) {
            case "-TS":
                trustStore=args[i+1];
                out=2;
                break;
            case "-TSPASS":
                trustStorePassword=args[i+1];
                out=2;
                break;
            case "-KS":
                keyStore=args[i+1];
                out=2;
                break;
            case "-KSPASS":
                keyStorePassword=args[i+1];
                out=2;
                break;
            case "-PORT":
                port=Integer.parseInt(args[i+1]);
                out=2;
                break;
            default:
                out=0;
                break;
        }
    }
    catch(Exception e) {
      // Something went wrong with the command-line parse.
      out=0;
    }

    return out;
  }

  /** Displays the command-line usage for SSLServerV2 */
  private void displayUsage()
  {
    System.out.println("Options:");
    System.out.println("\t-port\tport of server (default "+DEFAULT_PORT+")");
    System.out.println("\t-ts\ttruststore (default '"
                       +DEFAULT_TRUSTSTORE+"', JKS format)");
    System.out.println("\t-tspass\ttruststore password (default '"
                       +DEFAULT_TRUSTSTORE_PASSWORD+"')");
    System.out.println("\t-ks\tkeystore (default '"
                       +DEFAULT_KEYSTORE+"', JKS format)");
    System.out.println("\t-kspass\tkeystore password (default '"
                       +DEFAULT_KEYSTORE_PASSWORD+"')");
    
  }

  public SSLServerV2(String [] args)
  {
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

    else {
      // The command-line parse succeeded.
      // Construct a new instance of SSLServerV2
      SSLServerSocketFactory ssf;
        try {
            ssf = getSSLServerSocketFactory();
            serverSocketFactory=ssf;
        } catch (IOException | GeneralSecurityException ex) {
            Logger.getLogger(SSLServerV2.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
  }

  /**
   * SSLServerV2 is run as a separate Thread. The run() method
   * provides the main loop for the server. It runs as an infinite
   * loop; stop with Ctrl-C.
   */
  @Override
  public void run(){
    System.out.println("SSLServerV2 running on port "+port);

    try {
      // First, create the server socket on which we'll accept
      // connection requests. We require client authentication.
      SSLServerSocket sss=
        (SSLServerSocket)serverSocketFactory.createServerSocket(port);

      sss.setNeedClientAuth(true);

      // Each connection is given a numeric identifier, starting at 1.
      int id=1;

      // Listen for connection requests. For each request fire off a new
      // thread (the InputHandler) which echoes incoming text from the
      // stream to stdout.
      while(true) {
        String ids=String.valueOf(id++);

        // Wait for a connection request.
        SSLSocket ss=(SSLSocket)sss.accept();

        // We add in a HandshakeCompletedListener, which allows us to
        // peek at the certificate provided by the client.
        HandshakeCompletedListener x=new SimpleHandshakeListener(ids);
        ss.addHandshakeCompletedListener(x);

        InputStream ins=ss.getInputStream();
        OutputStream outs = ss.getOutputStream();
          InputHandler inputHandeler = new InputHandler(ids, ins, outs);
      }
    }
    catch(IOException ioe) {
      System.out.println("SimpleSSLServer failed with following exception:");
      System.out.println(ioe);
      ioe.printStackTrace();
    }
  }

  /**
   * Utility HandshakeCompletedListener which simply displays the
   * certificate presented by the connecting peer.
   */
  class SimpleHandshakeListener implements HandshakeCompletedListener
  {
    String ident;

    /**
     * Constructs a SimpleHandshakeListener with the given
     * identifier.
     */
    public SimpleHandshakeListener(String ident)
    {
      this.ident=ident;
    }

    /** Invoked upon SSL handshake completion. */
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent event)
    {
      // Display the peer specified in the certificate.
      try {
        X509Certificate cert=(X509Certificate)event.getPeerCertificates()[0];
        String peer=cert.getSubjectDN().getName();
        System.out.println(ident+": Request from "+peer);
      }
      catch (SSLPeerUnverifiedException pue) {
        System.out.println(ident+": Peer unverified");
      }
    }
  }
    

  /**
   * Utility thread class which simply forwards any text passed through
   * the supplied InputStream to stdout. An identifier is specified, which
   * preceeds forwarded text in stdout. InputHandler also logs its
   * progress to stdout.
   */
  class InputHandler extends Thread {
      
      ObjectInputStream ois;
      PrintWriter out;
      String ident;
      LogModule lm;
      Long id;

    /**
     * Constructs an InputHandler with the given identifier, around
     * the given InputStream and OutputStream.
     */
    InputHandler(String ident, InputStream is, OutputStream os)
    {
        this.ident=ident;
        log("New connection request");
        
        out = new PrintWriter(os, true);
        try {
            ois=new ObjectInputStream(is);
        } catch (IOException ex) {
            Logger.getLogger(SSLServerV2.class.getName()).log(Level.SEVERE, null, ex);
        }

      // Mark the thread as a Daemon, and start it.
      setDaemon(true);
      start();
    }

    /**
     * Sits in a loop on the reader, echoing each line to the screen.
     */
    @Override
    public void run()
    {
        String username;
        String password;
        boolean logged=false;
        lm= new LogModule();
        
        try {
            String[] line = null;
            byte[] decrypted = null;
            byte[] asn;
            while((asn= (byte[]) ois.readObject())!=null){
                decrypted = decryptData(asn);
                String verified =verify(decrypted);
                line= verified.substring(0, verified.length()).split(",");
                if (line[0].equals("login")) {
                    username=line[1];
                    password=line[2];
                    
                    try {
                        id= lm.login(username, password);
                        out.println("logged");
                        out.println(id);
                        out.flush();
                        logged=true;
                    } catch (AlreadyLoggedInException ex) {
                        out.println("al");
                        out.println(ex.getId());
                        out.flush();
                    } catch (RejectedException ex) {
                        out.println("F");
                        out.flush();
                    }
                }
                else if (line[0].equals("register")){
                    username=line[1];
                    password=line[2];
                    
                    try {
                        lm.registerUser(username, password);
                        out.println("registered");
                        out.flush();
                    } catch (RejectedException ex) {
                        out.println(ex.getMessage());
                        out.flush();
                    }
                }
                else if (line[0].equals("Logout")){
                    try {
                    lm.logout(id);
                    logged=false;
                    try {
                        ois.close();
                        out.close();
                    }
                    catch(IOException ioe) {
                    }
                    } catch (RejectedException ex) {
                        Logger.getLogger(SSLServerV2.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                else if(logged){
                    display(line[0]);
                }
            }
        }   catch(IOException ioe) {
            // Something went wrong. Log the exception and close.
            log(ioe.toString());
            log("Closing connection.");
        }   catch (ClassNotFoundException ex) {
            Logger.getLogger(SSLServerV2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(SSLServerV2.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Used to log progress
     */
    private void log(String text)
    {
      System.out.println(ident+": "+text);
    }

    /**
     * Used to echo text from the InputStream.
     * @param text Text to display to stdout, preceeded by the identifier
     */
    private void display(String text)
    {
        String x=text.substring(1);
        System.out.println(ident+"> "+x);
    }
  }
  
  private  SSLServerSocketFactory getSSLServerSocketFactory()
    throws IOException, GeneralSecurityException
  {
    // Call getTrustManagers to get suitable trust managers
    TrustManager[] tms=getTrustManagers();
    
    // Call getKeyManagers to get suitable
    // key managers
    KeyManager[] kms=getKeyManagers();

    // Next construct and initialise a SSLContext with the KeyStore and
    // the TrustStore. We use the default SecureRandom.
    SSLContext context=SSLContext.getInstance("SSL");
    context.init(kms, tms, null);

    // Finally, we get a ServerSocketFactory
    SSLServerSocketFactory ssf=context.getServerSocketFactory();
    return ssf;
  }
  
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
   
   protected KeyManager[] getKeyManagers()
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
   
    private String verify(byte [] asn) {
        byte[] buf= new byte[asn.length];
        String decoded = null;
        
        try {
            Security.addProvider(new IAIK());
            ASN1Object asn_obj = DerCoder.decode(asn);
            SignedData sd = new SignedData(asn_obj);

            // get the signer infos
            SignerInfo[] signerInfos = sd.getSignerInfos();
             // verify the signatures
            for (int i=0; i < signerInfos.length; i++) {
                try {
                    // verify the signature for SignerInfo at index i
                    X509Certificate cert = sd.verify(i);
                    // if the signature is OK the certificate of the signer is returned
                    System.out.println("Signature verified. signer certificate: ");
                    System.out.println(cert);
                    System.out.println();

                } catch (SignatureException ex) {
                    // if the signature is not OK a SignatureException is thrown
                    System.out.println("Signature ERROR from signer with certificate: ");
                    System.out.println(sd.getCertificate(signerInfos[i].getIssuerAndSerialNumber()));
                    System.out.println();
                    ex.printStackTrace();
                }
            }
            buf=sd.getContent();
            decoded=new String(buf, "UTF-8");
        } catch (Throwable thr) {
      thr.printStackTrace();
        }
        return decoded;
    }
    
    private byte[] decryptData(byte[] encryptedData) throws Exception{
        
        // initialise "BC" provider
        Security.addProvider(new BouncyCastleProvider());
        
        // read PrivateKey
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fileinputstream = new FileInputStream(keyStore);
        ks.load(fileinputstream, keyStorePassword.toCharArray());
        Key key = ks.getKey("server", keyStorePassword.toCharArray());
        PrivateKey privateKey = null;
        if (key instanceof PrivateKey) {
            privateKey = (PrivateKey) key;
        }
        
        // initialise parser
        CMSEnvelopedDataParser edp = new CMSEnvelopedDataParser(encryptedData);
        RecipientInformationStore ris = edp.getRecipientInfos();
        Collection envCollection = ris.getRecipients();
        Iterator it = envCollection.iterator();
        RecipientInformation recipient = (RecipientInformation) it.next();
        byte[] decoded=recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
        return decoded;
    }
}
