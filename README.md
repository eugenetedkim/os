Why is my project useful?
  I can use it as reference when I need to implement in a sychronization method.
What can other people do with my project?
  They can use it to have different processes/threads access the same resource without a race condition.
How can they use my project?
  They can use it by studying the use of semaphores as provided below in the lab and by referring to my notes.

Project: CSE 460 Operating Systems Lab 7

Lab 7, due 5/16/19 (Thu)
Dr. Tong Lai Yu

Semaphore Part II and XV6 System Calls

Shared Memory
A process can use IPC functions to create a range of address space that is also visible to other processes by 'attaching' the same shared memory segment into their own address space. All processes can access this shared memory locations just as if the memory had been created by new or malloc. The following are shared memory functions, which resemble those for semaphores:

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/shm.h>

int shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg );
int shmdt(const void *shmaddr);
int shmctl(int shmid, int cmd, struct shmid_ds *buf);
Use "man" to study each of the shared memory functions; write a brief description on the usage of each of them.

shmget ( shared memory get )

We create shared memory using shmget(), which allocates a shared memory segment. shmget() returns the identifier of the created shared memory segment associated with the value of the argument key; a new shared memory segment, with size equal to the value of size rounded up to a multiple of PAGE_SIZE, is created.

The parameter shmflg, consists of nine permission flags, which are used in the same way as the mode flags for creating files. A special bit defined by IPC_CREAT must be bitwise ORed with the permissions to create a new shared memory segment.

shmat ( shared memory attach )

When shared memory segment is first created, it is not accessible to any process. To enable access to the shared memory, we have to attach the shared memory to the address space of a process using shmat().

shmdt ( shared memory detach )

A process can detach the shared memory by using shmdt(). The input argument is a pointer to the shared memory returned by shmat().

shmctl ( shared memory control )

shmctl() allows the user to receive information on a shared memory segment, set the owner, group, and permissions of a shared memory segment, or destroy a segment. The information about the segment identified by shmid is returned in a shmid_ds structure:

           struct shmid_ds {
               struct ipc_perm shm_perm;  /* operation perms */
               size_t shm_segsz;          /* size of segment (bytes) */
               time_t shm_atime;          /* last attach time */
               time_t shm_dtime;          /* last detach time */
               time_t shm_ctime;          /* last change time */
               unsigned short shm_cpid;   /* pid of creator */
               unsigned short shm_lpid;   /* pid of last operator */
               short shm_nattch;          /* no. of current attaches */
               ...
           };
Try the following two programs that share a common memory area.

//shared1.cpp
/*  After the headers the shared memory segment
 (the size of our shared memory structure) is created with a call to shmget,
 with the IPC_CREAT bit specified. It reads data from the shared memory. */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define TEXT_SZ 2048

struct shared_use_st {
    int written_by_you;
    char some_text[TEXT_SZ];
};

int main()
{
    int running = 1;
    void *shared_memory = (void *)0;
    struct shared_use_st *shared_stuff;
    int shmid;

    srand((unsigned int)getpid());    

    shmid = shmget((key_t)1234, sizeof(struct shared_use_st), 0666 | IPC_CREAT);

    if (shmid == -1) {
        fprintf(stderr, "shmget failed\n");
        exit(EXIT_FAILURE);
    }

/* We now make the shared memory accessible to the program. */

    shared_memory = shmat(shmid, (void *)0, 0);
    if (shared_memory == (void *)-1) {
        fprintf(stderr, "shmat failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Memory attached at %X\n", shared_memory);

/* The next portion of the program assigns the shared_memory segment to shared_stuff,
 which then prints out any text in written_by_you. The loop continues until end is found
 in written_by_you. The call to sleep forces the consumer to sit in its critical section,
 which makes the producer wait. */

    shared_stuff = (struct shared_use_st *)shared_memory;
    shared_stuff->written_by_you = 0;
    while(running) {
        if (shared_stuff->written_by_you) {
            printf("You wrote: %s", shared_stuff->some_text);
            sleep( rand() % 4 ); /* make the other process wait for us ! */
            shared_stuff->written_by_you = 0;
            if (strncmp(shared_stuff->some_text, "end", 3) == 0) {
                running = 0;
            }
        }
    }

/* Lastly, the shared memory is detached and then deleted. */

    if (shmdt(shared_memory) == -1) {
        fprintf(stderr, "shmdt failed\n");
        exit(EXIT_FAILURE);
    }

    if (shmctl(shmid, IPC_RMID, 0) == -1) {
        fprintf(stderr, "shmctl(IPC_RMID) failed\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
/*
  shared2.cpp: Similar to shared1.cpp except that it writes data to
  the shared memory.
*/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define TEXT_SZ 2048

struct shared_use_st {
    int written_by_you;
    char some_text[TEXT_SZ];
};

int main()
{
    int running = 1;
    void *shared_memory = (void *)0;
    struct shared_use_st *shared_stuff;
    char buffer[BUFSIZ];
    int shmid;

    shmid = shmget((key_t)1234, sizeof(struct shared_use_st), 0666 | IPC_CREAT);

    if (shmid == -1) {
        fprintf(stderr, "shmget failed\n");
        exit(EXIT_FAILURE);
    }

    shared_memory = shmat(shmid, (void *)0, 0);
    if (shared_memory == (void *)-1) {
        fprintf(stderr, "shmat failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Memory attached at %X\n", shared_memory);

    shared_stuff = (struct shared_use_st *)shared_memory;
    while(running) {
        while(shared_stuff->written_by_you == 1) {
            sleep(1);
            printf("waiting for client...\n");
        }
        printf("Enter some text: ");
        fgets(buffer, BUFSIZ, stdin);

        strncpy(shared_stuff->some_text, buffer, TEXT_SZ);
        shared_stuff->written_by_you = 1;

        if (strncmp(buffer, "end", 3) == 0) {
                running = 0;
        }
    }

    if (shmdt(shared_memory) == -1) {
        fprintf(stderr, "shmdt failed\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
Compile and run shared1:

$ g++ -o shared1 shared1.cpp
$ ./shared1

Open another terminal to compile and run shared2:
$ g++ -o shared2 shared2.cpp
$ ./shared2
Type in some text at the terminals. What do you see? What text you enter will terminate the programs? Explain what you have seen.

Add a common semaphore, to shared1.cpp and shared2.cpp to protect the shared memory so that when a process accesses the shared area, the other is excluded from doing so. You may use the POSIX semaphore discussed, which is simpler or the UNIX semaphore discussed in Lab 6 to do this. (See the programs client.cpp and server.cpp below.) Test your modified programs to see if they work properly.

POSIX Semaphores
The semaphores we have described above are System V semaphores, which are quite complicated. POSIX defines a different set of semaphore functions which are easier to use. The potential learning curve of System V semaphores is much higher when compared to POSIX semaphores. This will be more understandable after you go through this section and compare it to what you learned in the previous section.

To start with, POSIX comes with simple semantics for creating, initializing, and performing operations on semaphores. They provide an efficient way to handle interprocess communication. POSIX comes with two kinds of semaphores: named and unnamed semaphores.

Named Semaphores

The advantage of named semaphores is that they provide synchronization between unrelated process and related process as well as between threads. ( Related processes refer to parent-child processes. ) A named semaphore is created by calling following function:

sem_t *sem_open(const char *name, int oflag, mode_t mode , int value);
where
name
    Is the name of the semaphore to be identified.
oflag
    Is set to O_CREAT for creating a semaphore (or with O_EXCL if you want the call to fail if it already exists).
mode_t
    Controls the permission setting for new semaphores.
value
    Specifies the initial value of the semaphore.
A single call creates the semaphore, initializes it, and sets permissions on it, which is quite different from the way System V semaphores act. It is much cleaner and more atomic in nature. Another difference is that the System V semaphore identifies itself by means of type int (similar to a fd returned from open()), whereas the sem_open function returns type sem_t, which acts as an identifier for the POSIX semaphores.
From here on, operations will only be performed on semaphores. The semantics for locking semaphores is:

int sem_wait(sem_t *sem);
This call is the DOWN function we have discussed. If the semaphore count is 1 (greater than zero), it decrements it by 1 and the semaphore is 'locked'. If the semaphore count is zero, the call blocks. This is done in an indivisible 'atomic' action.
The semantics for 'unlocking' ( UP ) a semaphore is:

int sem_post(sem_t *sem);
This call increases the semaphore count by 1, wakes up a sleeping ( blocked ) process and returns.
Once you're done using a semaphore, it is important to destroy it. To do this, make sure that all the references to the named semaphore are closed by calling the sem_close() function, then just before the exit or within the exit handler call sem_unlink() to remove the semaphore from the system. Note that sem_unlink() would not have any effect if any of the processes or threads reference the semaphore.

Unnamed Semaphores

Again, according to the man pages, an unnamed semaphore is placed in a region of memory that is shared between multiple threads (a thread-shared semaphore) or processes (a process-shared semaphore). A thread-shared semaphore is placed in a region where only threads of a process share them, for example, a global variable. A process-shared semaphore is placed in a region where different processes can share them, for example, something like a shared memory region. An unnamed semaphore provides synchronization between threads and between related processes and are process-based semaphores.

The unnamed semaphore does not need to use the sem_open call. Instead this one call is replaced by the following two instructions:

{ 
  sem_t semid; 
  int sem_init(sem_t *sem, int pshared, unsigned value); 
}
where
pshared
    This argument indicates whether this semaphore is to be shared between the threads of a process or between 
    processes. If pshared has value 0, then the semaphore is shared between the threads of a process. If pshared 
    is non-zero, then the semaphore is shared between processes.
value
    The value with which the semaphore is to be initialized.
Once the semaphore is initialized, the programmer is ready to operate on the semaphore, which is of type sem_t. The operations to lock and unlock the semaphore remains as shown previously: sem_wait(sem_t *sem) and sem_post(sem_t *sem). To delete a unnamed semaphore, just call the sem_destroy function.
Related Process

The processes are said to be related if the new process is created from within an existing process, which ends up in duplicating the resources of the creating process. Such processes are called related processes. The following example shows how the related processes are synchronized. You may execute "man mmap" to study the function mmap, which is used to map files or devices into memory and has the following prototypes:

       #include <sys/mman.h>

       void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
mmap() creates a new mapping in the virtual address space of the calling process. The following are the input parameters: 
addr
specifies the starting address for the new mapping.

length
specifies the length of the mapping.

prot
describes the desired memory protection of the mapping.

flags
determines whether updates to the mapping are visible to other processes mapping the same region, and whether updates are carried through to the underlying file.

fd
specifies the file descriptor.

offset
specifies the offset in the file (or other object) referred to by the file descriptor fd.
// semaphore1.cpp   
// Using POSIX semaphore for related processes
// compile:  g++ -o semaphore1 semaphore1.cpp -lpthread -lrt

#include <semaphore.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
  int fd, i,count=0,nloop=10,zero=0,*ptr;
  int shm;
  sem_t *mutex;
  //create shared memory
  if ((shm = shm_open("myshm", O_RDWR | O_CREAT, S_IRWXU))  < 0) {
    perror("shm_open");
    exit(1);
  }

  if ( ftruncate(shm, sizeof(sem_t)) < 0 ) {
    perror("ftruncate");
    exit(1);
   }

  if ((mutex = (sem_t*) mmap(  NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0)) == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }


  //open a file and map it into memory

  fd = open("log.txt",O_RDWR|O_CREAT,S_IRWXU);
  write(fd,&zero,sizeof(int));
  ptr = (int *) mmap(NULL,sizeof(int),PROT_READ |PROT_WRITE,MAP_SHARED,fd,0);
  close(fd);

  *ptr = 8;

  /* create, initialize semaphore */
  if( sem_init(mutex,1,1) < 0)
    {
      perror("semaphore initilization");
      exit(0);
    }
  if (fork() == 0) { /* child process*/
    for (i = 0; i < nloop; i++) {
      sem_wait(mutex);
      printf("child: %d\n", (*ptr)++);
      sem_post(mutex);
      sleep ( 1 );
    }
    exit(0);
  }
  /* back to parent process */
  for (i = 0; i < nloop; i++) {
    sem_wait(mutex);
    printf("parent: %d\n", (*ptr)++);
    sem_post(mutex);
    sleep ( 1 );
  }
  exit(0);
}
In this example, the related process access a common piece of memory, which is synchronized.
Try the example "semaphore1.cpp" and explain what you observe.

Unrelated Process

Processes are said to be unrelated if the two processes are unknown to each other and no relationship exists between them. For example, instances of two different programs are unrelated processes. If such programs try to access a shared resource, a semaphore could be used to synchronize their access. The following example demonstrates this:

// server.cpp
// g++ -o server server.cpp -lpthread -lrt
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define SHMSZ 27
char SEM_NAME[]= "vik";

int main()
{
  char ch;
  int shmid;
  key_t key;
  char *shm,*s;
  sem_t *mutex;

  //name the shared memory segment
  key = 1000;

  //create & initialize semaphore
  mutex = sem_open(SEM_NAME,O_CREAT,0644,1);
  if(mutex == SEM_FAILED)
    {
      perror("unable to create semaphore");
      sem_unlink(SEM_NAME);
      exit(-1);
    }

  //create the shared memory segment with this key
  shmid = shmget(key,SHMSZ,IPC_CREAT|0666);
  if(shmid<0)
    {
      perror("failure in shmget");
      exit(-1);
    }

  //attach this segment to virtual memory
  shm = (char*) shmat(shmid,NULL,0);

  //start writing into memory
  s = shm;
  for(ch='A';ch<='Z';ch++)
    {
      sem_wait(mutex);
      *s++ = ch;
      sem_post(mutex);
    }

  //the below loop could be replaced by binary semaphore
  while(*shm != '*')
    {
      sleep(1);
    }
  sem_close(mutex);
  sem_unlink(SEM_NAME);
  shmctl(shmid, IPC_RMID, 0);
  _exit(0);
}
// client.cpp
// g++ -o client client.cpp -lpthread -lrt
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define SHMSZ 27
char SEM_NAME[]= "vik";

int main()
{
  char ch;
  int shmid;
  key_t key;
  char *shm,*s;
  sem_t *mutex;

  //name the shared memory segment
  key = 1000;

  //create & initialize existing semaphore
  mutex = sem_open(SEM_NAME,0,0644,0);
  if(mutex == SEM_FAILED)
    {
      perror("reader:unable to execute semaphore");
      sem_close(mutex);
      exit(-1);
    }

  //create the shared memory segment with this key
  shmid = shmget(key,SHMSZ,0666);
  if(shmid<0)
    {
      perror("reader:failure in shmget");
      exit(-1);
    }

  //attach this segment to virtual memory
  shm = (char*) shmat(shmid,NULL,0);

  //start reading
  s = shm;
  for(s=shm;*s!=0;s++)
    {
      sem_wait(mutex);
      putchar(*s);
      sem_post(mutex);
    }

  //once done signal exiting of reader:This can be replaced by another semaphore
  *shm = '*';
  sem_close(mutex);
  shmctl(shmid, IPC_RMID, 0);
  exit(0);
}
The above executables (client and server) demonstrate how semaphore could be used between completely different processes.

In addition to the applications shown above, semaphores can be used cooperatively to access a resource. Please note that a semaphore is not a Mutex. A Mutex allows serial access to a resource, whereas semaphores, in addition to allowing serial access, could also be used to access resources in parallel. For example, consider resource R being accessed by n number of users. When using a Mutex, we would need a Mutex "m" to lock and unlock the resource, thus allowing only one user at a time to use the resource R. In contrast, semaphores can allow n number of users to synchronously access the resource R.

Try the server-client example above and explain what you observe. You have to start the server first ( why ? ). Modify the programs so that the server sits in a loop to accept string inputs from users and send them to the client, which then prints out the string.
XV6 System Calls
Adding New System Calls 
A system call is simply a kernel function that a user application can use to access or utilize system resources. Functions fork(), and exec() are well-known examples of system calls in UNIX and xv6. In this lab, we will use a simple example to walk you through the steps of adding a new system call to xv6. We name the system call cps(), which prints out the current running and sleeping processes.

An application signals the kernel it needs a service by issuing a software interrupt, a signal generated to notify the processor that it needs to stop its current task, and response to the signal request. Before switching to handling the new task, the processor has to save the current state, so that it can resume the execution in this context after the request has been handled. The following is a code that calls a system call in xv6 (found in initcode.S):

.globl start
start:
  pushl $argv
  pushl $init
  pushl $0  // where caller pc would be
  movl $SYS_exec, %eax
  int $T_SYSCALL
Basically, it pushes the argument of the call to the stack, and puts the system call number, which is $SYS_exec in the example, into %eax. All the system call numbers are specified and saved in a table and the system calls of xv6 can be found in the file syscall.h. 
Next, the code int $T_SYSCALL generates a software interrupt, indexing the interrupt descriptor table to obtain the appropriate interrupt handler. The function trap() (in trap.c) is the specific code that finds the appropriate interrupt handler. It checks whether the trap number in the generated trapframe (a structure representing the processor's state at the time the trap happened) is equal to T_SYSCALL. If it is, it calls syscall(), the software interrupt handler that's available in syscall.c.
// This is the part trap that calls syscall()
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(proc->killed)
      exit();
    proc->tf = tf;
    syscall();
    if(proc->killed)
      exit();
    return;
  }
  .....
}
The function syscall() is the final function that checks out %eax to obtain the system call's number, which is used to index the table with the system call pointers, and to execute the code corresponding to that system call:
void
syscall(void)
{
  int num;

  num = proc->tf->eax;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    proc->tf->eax = syscalls[num]();
  } else {
    cprintf("%d %s: unknown sys call %d\n",
            proc->pid, proc->name, num);
    proc->tf->eax = -1;
  }
}
The following are the procedures of adding our exemplary system call cps() to xv6.

Add name to syscall.h:
// System call numbers
#define SYS_fork    1
..........
#define SYS_close  21
#define SYS_cps    22

Add function prototype to defs.h:
// proc.c
void            exit(void);
......
void            yield(void);
int             cps ( void );

Add function prototype to user.h:
// system calls
int fork(void);
.....
int uptime(void);
int cps ( void );

Add function call to sysproc.c:
int
sys_cps ( void )
{
  return cps ();
}

Add call to usys.S:
SYSCALL(cps)

Add call to syscall.c:
extern int sys_chdir(void);
.....
extern int sys_cps(void);
.....
static int (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
.....
[SYS_close]   sys_close,
[SYS_cps]     sys_cps,
};

Add code to proc.c:
//current process status
int
cps()
{
  struct proc *p;
  
  // Enable interrupts on this processor.
  sti();

    // Loop over process table looking for process with pid.
  acquire(&ptable.lock);
  cprintf("name \t pid \t state \n");
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if ( p->state == SLEEPING )
        cprintf("%s \t %d  \t SLEEPING \n ", p->name, p->pid );
      else if ( p->state == RUNNING )
        cprintf("%s \t %d  \t RUNNING \n ", p->name, p->pid );
  }
  
  release(&ptable.lock);
  
  return 22;
}

Create testing file ps.c with code shown below:
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

int
main(int argc, char *argv[])
{
  cps();

  exit();
}

Modify Makefile:
Modify Makefile to include ps.c as discussed in class.
After you have compiled and run "$make qemu-nox", you can execute the command "$ps" inside xv6. You should see outputs similar to the following:

 name 	 pid 	 state 
init 	 1  	 SLEEPING 
 sh 	 2  	 SLEEPING 
 ps 	 3  	 RUNNING 

See video Adding a system call to xv6 (with caption) .
Work to do

Do the experiment as described above. Copy-and-paste your outputs and commands to your report.
Modify cps() in proc.c so that it returns the total number of processes that are SLEEPING or RUNNING. Modify ps.c so that it prints out a message telling the total number of SLEEPING and RUNNING processes. Copy your code and outputs to your report.
Report 
Write a report that shows all your work; make sample screen shots of your graphics outputs if there is any, otherwise, use script to capture your text outputs and copy-and-paste into your report. Include in your report the text source codes of your programs. Comment on and self-evaluate your work; state explicitly whether you have finished each part successfully! If you have finished all parts successfully, give yourself 20 points, otherwise, deduct some points that you feel appropriate. The instructor may adjust your score depending on your submitted report.
Note: All your work must be saved in pdf file format and submitted online! Typically, your submitted pdf file should have some program text outputs captured by the script command. You must also put down your name but not your student ID's in your submitted report. To submit your lab, you must first login by choosing your name, entering your student id, and clicking Login below. 
After submission, click on the link displayed, to make sure you could see what you have submitted with your browser. 
