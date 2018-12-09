#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "devices/shutdown.h"
//#include "userprog/process.c"

typedef int pid_t;

struct process_file {
  struct file* file;
  int fd;
  struct list_elem elem;
};

//partiks code start
struct child{
  int pid;
  struct thread *parent_pid;
  int alive; //0 means dead and 1 means alive
  int exit_status;
  struct list_elem elem;
};
//partiks code end

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

int INVALID = -1;

void syscall_init (void) 
{
  lock_init(&file_lock);
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct file* obtain_file(int fd){
  struct thread *th = thread_current();
    struct list_elem* next;
    struct list_elem* e;
    e = list_begin(&th->files);
    //("BEGIN");
    while(e!=list_end(&th->files)){
      next = list_next(e);
      //("NEXT");
      struct process_file* pro = list_entry(e, struct process_file, elem);
      if (pro->fd == fd){
        //("END");
        return pro->file;
      }
      e = next;
    }
    //("NUlll");
    return NULL;
}


void halt(){
  shutdown_power_off();
}

void exit(int status){
  //thread_current()->exit_status = status;

  struct child *b = (struct child *) malloc(sizeof(struct child));
  for(struct list_elem* c = list_begin(&thread_current()->parent_pid->child_list); c != list_end(&thread_current()->child_list); c = list_next(c))
  {
    b = list_entry(c,  struct child, elem);
    if (b->pid == thread_current()->tid)
    {
      b->exit_status = 0;
    }
    else{
      printf("NEVER SHOULD'VE COME HERE EXIT()\n");
      //check for already dead child processes in wait_log
    }
  }

  printf("%s: exit(%d)\n", thread_current()->name, status);
  //process_exit();
  thread_exit();
}

int wait(pid_t pid){

}

bool create(const char* file, unsigned initial_size){
  bool result;
  lock_acquire(&file_lock);
  result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

bool remove(const char* file){
  bool result;
  lock_acquire(&file_lock);
  result = filesys_remove(file);
  lock_release(&file_lock);
  return result;

}

int open(const char* file){
  int fd;
  struct process_file* proce = malloc(sizeof(struct process_file));
  proce->file = file;
  fd = thread_current()->file_descriptor;
  proce->fd = thread_current()->file_descriptor;
  thread_current()->file_descriptor++;
  list_push_back(&thread_current()->files, &proce->elem);
  return fd;
}

int filesize(const char* file_input){
  int size;
  size = file_length(file_input);
  return size;
}

int read(int fd, void* buffer, unsigned size){
  int len;
  if (fd == 0){
    unsigned i = 0;
    uint8_t *local_buf = (uint8_t *) buffer;
    while(i<size){
      local_buf[i]=input_getc();
      i++;
    }
    return size;
  }
  lock_acquire(&file_lock);
  struct file *file_input = obtain_file(fd);
      if(!file_input){
        lock_release(&file_lock);
        return INVALID ;
      }
    len = file_read(file_input, buffer, size);
  lock_release(&file_lock);
  return len;
}

int write(int fd, const void* buffer, unsigned size){
  int len;
  if (fd == 1){
    putbuf (buffer, size); // from stdio.h
    //("PUTBUF %d\n",size);
        return size;
  }

  lock_acquire(&file_lock);
  //("OBTAIN\n");
  struct file *file_input = obtain_file(fd);
      if(!file_input){
        lock_release(&file_lock);
        return INVALID;
      }
    len = file_write(file_input, buffer, size);
  lock_release(&file_lock);
  return len;
}

void seek(const char* file, unsigned position){
  file_seek(file, position);
}

unsigned tell(const char* file){
  off_t off;
  off = tell(file);
  return off;

}

void close(int fd){

}


void check_adr(const char *adr_to_check){
  //printf("%p", adr_to_check );
  if(!is_user_vaddr (adr_to_check)){
    //printf("is_user_vaddr\n");
    exit(INVALID);
  }
  else if(adr_to_check == NULL){
    //printf("NULLLL \n");
    exit(INVALID);
  }

  else if(adr_to_check < (void *) 0x08048000){
    //printf("virtual addre \n");
    exit(INVALID);
  }

}

int check_page(char *page_to_check){
  void *pntr_page = pagedir_get_page(thread_current()->pagedir, page_to_check);
    if (!pntr_page){
      exit(INVALID);
    }
    
    return (int) pntr_page;
}


static void syscall_handler (struct intr_frame *f UNUSED) 
{
  ("SYSCALL HANDLER REACHED\n\n");
    int *adr = f->esp;
    int adr2 = *adr;
    check_adr(adr);
      //(" lod o %d \n",adr2);
      //("THREAD %d \n",thread_current()->tid);
    switch(adr2){

      case SYS_HALT:
      {
        shutdown_power_off();
        break;
      }

      case SYS_EXIT:
      {
        int stts = *((int*)f->esp +1);
        exit(stts);
        break;
      }

      case SYS_EXEC:
      {
        //printf("AYU \n");
        char* cmdline = (* ((int *) f->esp + 1));
        //printf("BAHU AYU\n");
        check_adr(cmdline);

        cmdline = check_page((const char*)cmdline);
        thread_current()->isparent=1;
        f->eax = process_execute(cmdline);
        break;
      }

      case SYS_WAIT:
      {
        printf("-------------------------CALLED WAIT\n\n");
        int *proid = (* ((int *) f->esp + 1));
        check_adr((const void *) proid);
        f->eax = process_wait(proid);
        break;
      }
  
      case SYS_CREATE:
      {
        char *fle = (char *) (* ((int *) f->esp + 1));
        unsigned int_size = *((int*)f->esp +2);
        //printf("1st stage \n \n");
        check_adr(fle);
        //printf("2nd stage \n \n");
        //check_adr(int_size );
        //printf("3rd one \n \n");
        fle = check_page(fle);
        //printf("final");
        f->eax = create(fle, int_size);
        //printf("last");
        break;
       }

    case SYS_REMOVE:
    {
        char *fle = (char *) (* ((int *) f->esp + 1));
        check_adr((const void *) fle);
        fle = check_page((const void *)fle);
        f->eax = remove((const void*) fle);
        break;
       }

    case SYS_OPEN:
    {
        char *fle = (char *) (* ((int *) f->esp + 1));
        check_adr((const void *) fle);
        fle = check_page((const void *)fle);
        lock_acquire(&file_lock);
        struct file* file_get = filesys_open(fle);
      if(file_get == NULL){
         lock_release(&file_lock);
      return INVALID;
      }
        f->eax = open((const void*) file_get);
        lock_release(&file_lock);
        break;
       }

      case SYS_FILESIZE:
      {
        int fd = *((int*)f->esp + 1);
        //check_adr((const void *) fd);
        lock_acquire(&file_lock);
        struct file *file_input = obtain_file(fd);
        if(file_input){
          f->eax = filesize((const void*) file_input);
          lock_release(&file_lock);
        }
        else{
          lock_release(&file_lock);
          exit(INVALID);
        }
        break;
       }

      case SYS_READ:
        {
          int fd = *((int*)f->esp + 1);
          void* buffer = (void*)(*((int*)f->esp + 2));
          unsigned size = *((unsigned *) f-> esp + 3);
         //check_adr(fd);
           check_adr(buffer);
         //check_adr(size);
        
          char *temp_buff = (char *)buffer;
          while(temp_buff<size)
          {
            check_adr(temp_buff);
            temp_buff++;
          }
          buffer = check_page(buffer);
          f->eax = read(fd, buffer, (unsigned)size);
          break;
      }

      case SYS_WRITE:
      {
        int fd = *((int*)f->esp + 1);
        void* buffer = (void*)(*((int*)f->esp + 2));
        unsigned size = *((unsigned *) f-> esp + 3);
       //check_adr(fd);
         check_adr(buffer);
       //check_adr(size);
      
      char *temp_buff = (char *)buffer;
        while(temp_buff<size){
          check_adr(temp_buff);
          temp_buff++;
        }
        buffer = check_page(buffer);
        f->eax = write(fd, buffer, (unsigned)size);
        break;
      }
  
      case SYS_SEEK:
      {
        int fd = *((int*)f->esp + 1);
        unsigned position = *((unsigned *) f-> esp + 2);
        lock_acquire(&file_lock);
        struct file *file_input = obtain_file(fd);
        if(file_input){
          seek((const void*) file_input , position);
          lock_release(&file_lock);
        }
        else{
          lock_release(&file_lock);
          exit(INVALID);
        }
        break;
       }

      case SYS_TELL:
      {
        int fd = *((int*)f->esp + 1);
        lock_acquire(&file_lock);
        struct file *file_input = obtain_file(fd);
        if(file_input){
          f->eax = tell((const void*) file_input);
          lock_release(&file_lock);
        }
        else{
          lock_release(&file_lock);
          exit(INVALID);
        }
        break;
       }

      case SYS_CLOSE:
      {
        int fd = *((int*)f->esp + 1);
        close(fd);
        break;
      }
    }

}
