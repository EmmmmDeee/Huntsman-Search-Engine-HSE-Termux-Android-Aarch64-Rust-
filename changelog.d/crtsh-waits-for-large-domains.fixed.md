- crt.sh lookups now wait 75 seconds instead of 30. A large organisation's certificate history
  takes crt.sh longer to begin answering (`telstra.com.au` took 39 seconds), so every `domain`
  lookup and `recon crtsh` of such a domain timed out and lost all its certificate subdomains.
