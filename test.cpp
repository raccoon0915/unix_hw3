#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sstream>
#include "ptools.h"
#include <cstring>
#include <string.h>
#include <iostream>
#include <fcntl.h>
#include<iomanip>
using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void dump_code(long addr, long code) {
	fprintf(stderr, "## %lx: code = %02x %02x %02x %02x %02x %02x %02x %02x\n",
		addr,
		((unsigned char *) (&code))[0],
		((unsigned char *) (&code))[1],
		((unsigned char *) (&code))[2],
		((unsigned char *) (&code))[3],
		((unsigned char *) (&code))[4],
		((unsigned char *) (&code))[5],
		((unsigned char *) (&code))[6],
		((unsigned char *) (&code))[7]);
}

int main(int argc, char *argv[]) {
	pid_t child;
	char program[50]; 
	if(argc > 1) {
		sprintf(program, "./%s", argv[1]);
	}
#if 0 //raccoon: load done
	int fd = open(program, O_RDONLY);
	lseek(fd, 24, SEEK_SET);
	unsigned long entry_point;
	read(fd, &entry_point, sizeof(entry_point));
	cout << "** program '" << program << "' loaded. entry point " << hex << entry_point << endl;
#endif
#if 1	//raccoon:parse prototype
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execlp(program, program, NULL);
		errquit("execvp");
	}
	else{
		while(true){
			char temp[50];
			cout << "sdb> ";
			cin >> temp;
			if(!strcmp(temp, "b") || !strcmp(temp, "break")) cout << "do b or break\n";
			if(!strcmp(temp, "start")){	//raccoon:start done	
				cout << "** pid " << child << endl;	
			}
			if(!strcmp(temp, "get") || !strcmp(temp, "g")){	//raccoon:get or g done
				struct user_regs_struct regs;
				cin >> temp;
				if(!strcmp(temp, "rax")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rax = " << regs.rax << " (" << hex << regs.rax << ")\n";}	//raccoon:There is something trobule here, get twice rip = 0x4000b0
				else if(!strcmp(temp, "rbx")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rbx = " << regs.rbx << " (" << hex << regs.rbx << ")\n";}
				else if(!strcmp(temp, "rcx")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rcx = " << regs.rcx << " (" << hex << regs.rcx << ")\n";}
				else if(!strcmp(temp, "rdx")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rdx = " << regs.rdx << " (" << hex << regs.rdx << ")\n";}
				else if(!strcmp(temp, "r8")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r8 = " << regs.r8 << " (" << hex << regs.r8 << ")\n";}
				else if(!strcmp(temp, "r9")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r9 = " << regs.r9 << " (" << hex << regs.r9 << ")\n";}
				else if(!strcmp(temp, "r10")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r10 = " << regs.r10 << " (" << hex << regs.r10 << ")\n";}
				else if(!strcmp(temp, "r11")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r11 = " << regs.r11 << " (" << hex << regs.r11 << ")\n";}
				else if(!strcmp(temp, "r12")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r12 = " << regs.r12 << " (" << hex << regs.r12 << ")\n";}
				else if(!strcmp(temp, "r13")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r13 = " << regs.r13 << " (" << hex << regs.r13 << ")\n";}
				else if(!strcmp(temp, "r14")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r14 = " << regs.r14 << " (" << hex << regs.r14 << ")\n";}
				else if(!strcmp(temp, "r15")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "r15 = " << regs.r15 << " (" << hex << regs.r15 << ")\n";}
				else if(!strcmp(temp, "rdi")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rdi = " << regs.rdi << " (" << hex << regs.rdi << ")\n";}
				else if(!strcmp(temp, "rsi")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rsi = " << regs.rsi << " (" << hex << regs.rsi << ")\n";}
				else if(!strcmp(temp, "rbp")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rbp = " << regs.rbp << " (" << hex << regs.rbp << ")\n";}
				else if(!strcmp(temp, "rsp")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rsp = " << regs.rsp << " (" << hex << regs.rsp << ")\n";}
				else if(!strcmp(temp, "rip")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "rip = " << regs.rip << " (" << hex << regs.rip << ")\n";}
				else if(!strcmp(temp, "flags")){
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
					cout << "flags = " << regs.eflags << " (" << hex << setw(16) << setfill('0') << regs.eflags << ")\n";}
				else cout << "pls input register\n";
			}
			if(!strcmp(temp, "run") || !strcmp(temp, "r")) ptrace(PTRACE_CONT, child, 0, 0);	//raccoon:run yet done
		}
	}
#endif
#if 0	//racoon:vvmap done
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execlp(program, program, NULL);
		errquit("execvp");
	} else {
		int status;
		unsigned long baseaddr, target, code;
		map<range_t, map_entry_t> vmmap;
		map<range_t, map_entry_t>::iterator vi;

		if(waitpid(child, &status, 0) < 0) errquit("waitpid");
		assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		if(load_maps(child, vmmap) <= 0) {
			fprintf(stderr, "## cannot load memory mappings.\n");
			return -1;
		}
		fprintf(stderr, "## %zu map entries loaded.\n", vmmap.size());

		for(vi = vmmap.begin(); vi != vmmap.end(); vi++) {
			string perm;
			perm.push_back((vi->second.perm & 4) == 0 ? '-' : 'r');
			perm.push_back((vi->second.perm & 2) == 0 ? '-' : 'w');
			perm.push_back((vi->second.perm & 1) == 0 ? '-' : 'x');
			cout << hex << setw(16) << setfill('0') << vi->first.begin << "-" << hex << setw(16) << setfill('0') << vi->first.end << " " << perm << " " << vi->second.offset << " " << vi->second.name << endl;
		} 
#endif		
#if 0
		target = baseaddr;
		fprintf(stderr, "## baseaddr = 0x%zx, target = 0x%zx.\n", baseaddr, target);

		/* get original text: 48 39 d0 */
		code = ptrace(PTRACE_PEEKTEXT, child, target, 0);
		dump_code(target, code);
		/* set break point */		
		if(ptrace(PTRACE_POKETEXT, child, target, (code & 0xffffffffffffff00) | 0xcc) != 0)
			errquit("ptrace(POKETEXT)");
		/* continue the execution */
		ptrace(PTRACE_CONT, child, 0, 0);
#endif 
#if 0
		while(waitpid(child, &status, 0) > 0) {
			struct user_regs_struct regs;
			if(!WIFSTOPPED(status)) continue;
			if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
				errquit("ptrace(GETREGS)");
			if(regs.rip-1 == target) {
				/* restore break point */
				if(ptrace(PTRACE_POKETEXT, child, target, code) != 0)
					errquit("ptrace(POKETEXT)");
				/* set registers */
				regs.rip = regs.rip-1;
				regs.rdx = regs.rax;
				if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
			}
			ptrace(PTRACE_CONT, child, 0, 0);
		}
#endif
	return 0;
}

