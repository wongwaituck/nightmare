FROM i386/ubuntu:xenial

RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
RUN apt-get install -y xinetd build-essential
RUN apt-get install -y gcc-multilib
ENV user=ctf
ENV binary=pwn1
RUN useradd -m $user
RUN echo "$user     hard    nproc       20" >> /etc/security/limits.conf

COPY ./$binary /home/$user/bin
COPY ./service /etc/xinetd.d/$userservice

RUN chown -R root:$user /home/$user
RUN chmod -R 750 /home/$user
COPY ./flag.txt /flag.txt
#RUN echo "FLAG{WIN}" > /home/$user/flag

USER $user

EXPOSE 1337
ENTRYPOINT ["/usr/sbin/xinetd", "-dontfork"]
