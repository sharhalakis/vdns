class Config:
    olddir      = '/etc/bind/db'    # Directory that stores existing config
    outdir      = 'db/'
    keydir      = 'keys/'

    dbname      = 'dns'
    dbuser      = None
    dbpass      = None
    dbhost      = None
    dbport      = 5432

    domains     = []
    networks    = []
    doall       = False     # Do all domains/networks?
    dokeys      = False     # Export keys?

    incserial   = True      # Increment serial number?

if __name__=="__main__":
    pass

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:

