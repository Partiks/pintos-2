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

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

int INVALID = -44;

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
  	printf("BEGIB");
  	while(e!=list_end(&th->files)){
  		next = list_next(e);
  		printf("NEXT");
  		struct process_file* pro = list_entry(e, struct process_file, elem);
  		if (pro->fd == fd){
  			printf("END");
  			return pro->file;
  		}
  		e = next;
  	}
  	printf("NUlll");
  	return NULL;
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
	printf("SYSCALL HANDLER REACHED\n\n");
  	int *adr = f->esp;
  	int adr2 = *adr;
  	check_adr(adr);
  		printf(" lod o %d \n",adr2);
  		printf("THREAD %d \n",thread_current()->tid);
  	switch(adr2){

	  	case SYS_HALT:
	  	{
	  		halt();
	  		break;
	  	}

	  	case SYS_EXIT:
	  	{
	  		printf("CHUTiya");
	  		int *stts = *((int*)f->esp +1);
	  		printf("STTS - 1\n");
	  		check_adr((const void *) stts);
	  		printf("STTS CHECK ADDR - 2 %d \n",stts);
	  		exit(stts);
	  		printf("ADR EIT = %d",adr2);
	  		break;
	  	}

	  	case SYS_EXEC:
	  	{
	  		printf("ADR EXEC = %d",adr2);
	  		printf("WHY THE HELL IS THiS SHIT HERE \n\n");
	  		const char* cmdline = (char *) (* ((int *) f->esp + 1));
	  		check_adr((const void *) cmdline);
		    cmdline = check_page((const void *) cmdline);
	  		f->eax = my_exec((const void*) cmdline);
	  		break;
	  	}

	  	case SYS_WAIT:
	  	{
	  		int *proid = ++(*adr);
	      	check_adr((const void *) proid);
	      	f->eax = process_wait(proid);
	      	break;
	    }
	/*
	  	case SYS_CREATE:
	      int *fle = ++(*adr);
	      int *int_size = *(adr+2);
	      check_adr((const void *)fle);
	      check_adr((const void *)int_size);
	      fle = check_page((const void *)fle);
	      f->eax = create((const void*) fle, int_size);
	      break;

	  	case SYS_REMOVE:
	      int *fle = ++(*adr);
	      check_adr((const void *) fle);
	      fle = check_page((const void *)fle);
	      f->eax = remove((const void*) fle);
	      break;

	  	case SYS_OPEN:
	      int *fle = ++(*adr);
	      check_adr((const void *) fle);
	      fle = check_page((const void *)fle);
	      lock_acquire(&file_lock);
	      f->eax = open((const void*) fle);
	      lock_release(&file_lock);
	      break;

	  	case SYS_FILESIZE:
	      int *fd = ++(*adr);
	      check_adr((const void *) fd);
	      lock_acquire(&file_lock);
	      struct file *file_input = obtain_file(fd)
	      if(file_input){
	        f->eax = filesize((const void*) file_input);
	        lock_release(&file_lock);
	      }
	      else{
	        lock_release(&file_lock);
	        exit(INVALID);
	      }
	      break;

	  	case SYS_READ:
	      int *fd = ++(*adr);
	      int *buff = *(adr+2);
	      int *sze = *(adr+3);
	   
	      check_adr((const void *)fd);
	      check_adr((const void *)buff);
	      check_adr((const void *)sze);
		  
		  char *temp_buff = (char *)buff
	      while(temp_buff<sze){
	      	check_adr(temp_buff);
	      	temp_buff++;
	      }

	      buff = check_page((const void *)buff);
	      
	      f->eax = read(fd, (const void*) buff, (unsigned)sze);
	      break;
	*/
	  	case SYS_WRITE:
	  	{
	  		printf("WEIRD WRITE CALL\n\n");
	      //int *fd = ++(*adr);
	  		int fd = *((int*) f->esp + 1);
	      void* buffer = (void *) (* ((int *) f->esp + 2));
	      unsigned size = *((unsigned *) f-> esp + 3);
	   
	      check_adr((const void *)fd);
	      check_adr(buffer);
	      check_adr((const void *)size);
		  
		  char *temp_buff = (char *)buffer;
	      while(temp_buff<size){
	      	check_adr(temp_buff);
	      	temp_buff++;
	      }
	      buffer = check_page((const void *)buffer);
	      
	      f->eax = write(fd, buffer, (unsigned)size);
	      break;
	  	}
	/*
	  	case SYS_SEEK:
	      int *fd = ++(*adr);
	      int *pos = *(adr+2);
	      check_adr((const void *)fd);
	      check_adr((const void *)pos);=
	      lock_acquire(&file_lock);
	      struct file *file_input = obtain_file(fd)
	      if(file_input){
	        f->eax = seek((const void*) file_input , pos);
	        lock_release(&file_lock);
	      }
	      else{
	        lock_release(&file_lock);
	        exit(INVALID);
	      }
	      break;

	  	case SYS_TELL:
	      int *fd = ++(*adr);
	      check_adr((const void *) fd);
	      lock_acquire(&file_lock);
	      struct file *file_input = obtain_file(fd)
	      if(file_input){
	        f->eax = tell((const void*) file_input);
	        lock_release(&file_lock);
	      }
	      else{
	        lock_release(&file_lock);
	        exit(INVALID);
	      }
	      break;

	  	case SYS_CLOSE:
	      int *fd = ++(*adr);
	      check_adr((const void *) fd);
	      close(fd);
	      break;
	 */
	      default:
	      printf("DEFAULT CAME FROM SWITCH IN SYSCALL.c\n");
	      thread_exit();
	      break;
  	}

}


void halt(){
	shutdown_power_off();
}

void exit(int status){
	printf("MEA EXIT AYA %d\n\n",status);
	//thread_exit();
}

pid_t my_exec(const char* cmd_line){
	printf("MY_EXEC FUNTION HERE FROM SYSCALL.C\n");

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
        exit(INVALID);
      }
    len = file_read(file_input, buffer, size);
	lock_release(&file_lock);
	return len;
}

int write(int fd, const void* buffer, unsigned size){
	int len;
	printf("FD BHOS = %d \n",fd);
	if (fd == 1){
		putbuf (buffer, size); // from stdio.h
		printf("PUTBUF %d\n",size);
      	return size;
	}

	lock_acquire(&file_lock);
	printf("OBTAIN\n");
	struct file *file_input = obtain_file(fd);
      if(!file_input){
        lock_release(&file_lock);
        exit(INVALID);
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
	if(!is_user_vaddr (adr_to_check)){
		exit(INVALID);
	}
	else if(adr_to_check == NULL){
		exit(INVALID);
	}
	else if(adr_to_check < (void *)0x08048000){
		exit(INVALID);
	}

	void *pntr_page = pagedir_get_page(thread_current()->pagedir, adr_to_check);
  	if (!pntr_page){
      exit(INVALID);
    }
  	
  	return (int) pntr_page;
}

void check_page(const char *page_to_check){
	void *pntr_page = pagedir_get_page(thread_current()->pagedir, page_to_check);
  	if (!pntr_page){
      exit(INVALID);
    }
  	
  	return (int) pntr_page;
}
