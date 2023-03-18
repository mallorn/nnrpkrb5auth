CFLAGS		= -O6 -c -I/usr/local/krb5/include
LFLAGS		= -s -L/usr/local/krb5/lib
LIBS		= -lkrb5 -lresolv -lk5crypto -lcom_err
SRCS		= nnrpkrb5auth.c
OBJS		= nnrpkrb5auth.o

all:		nnrpkrb5auth

.c.o:		$(CC) $(CFLAGS) $<

nnrpkrb5auth:	$(OBJS)
		$(CC) $(LFLAGS) $(OBJS) -o nnrpkrb5auth $(LIBS)

clean:		
		rm -f *.o nnrpkrb5auth core
