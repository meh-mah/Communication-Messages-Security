/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;

/**
 *
 * @author M&M
 */
public class AliasChoosingKeyManager implements X509KeyManager
  {
    X509KeyManager baseKM=null;
    String alias=null;

    /**
     * @param keyManager the X509KeyManager to wrap
     * @param alias the alias to force
     */
    public AliasChoosingKeyManager(X509KeyManager keyManager, String alias)
    {
      baseKM=keyManager;
      this.alias=alias;
    }

    /**
     * selects an alias to authenticate the client side
     * of a SSL connection. This implementation uses getClientAliases to
     * find a list of valid aliases and checks the requested alias against
     * this list. If the requested alias is valid, it is returned; otherwise
     * null is returned.
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
                                    Socket socket)
    {
      // For each keyType, call getClientAliases on the base KeyManager
      // to find valid aliases. If our requested alias is found, select it
      // for return.
      boolean found=false;

      for (int i=0; i<keyType.length && !found; i++) {
        String[] valid=baseKM.getClientAliases(keyType[i], issuers);
        if (valid!=null) {
          for (int j=0; j<valid.length && !found; j++) {
            if (valid[j].equals(alias)) found=true;
          }
        }
      }

      if (found) return alias;
      else return null;
    }

    // The other methods simply drop through to the base KeyManager.

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers,
                                    Socket socket)
    {
      return baseKM.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
      return baseKM.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
      return baseKM.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias)
    {
      return baseKM.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
      return baseKM.getServerAliases(keyType, issuers);
    }
  }
