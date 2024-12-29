#include <linux/sched.h>
#include <linux/fdtable.h>
struct data_t {
    u64 syscallnum;
    u64 time;
    char pathname1[128];
    char pathname2[128];
};


// トレースするプロセスを指定するためのハッシュテーブルを定義
// シェルスクリプト内で生成されたプロセス(つまり親プロセスになりうるプロセス)のPIDを保持する
// ppidlist内に格納されているPPIDを持つプロセスのみを監視する
BPF_HASH(ppidlist, int, int);
BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx){
    //execveが発行されたら，そのプロセスの親プロセスが何かを判定し，PIDをppidlistに書き込む
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = task->real_parent->tgid;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int *p;

    p = ppidlist.lookup(&ppid); //PPIDがBPF MAPに存在するか判定

    if(p != 0){//この中に行いたい処理を書く
        ppidlist.update(&pid, &ppid); //PIDを登録
    }
    
    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *pathname){
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = task->real_parent->tgid;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int *p;

    p = ppidlist.lookup(&ppid); //PPIDがBPF MAPに存在するか判定
    if(p != 0){
        //if(pathname[9] == 's'){
            data.syscallnum = 1;
            data.time = bpf_ktime_get_ns();
            //bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_user(&data.pathname1, sizeof(data.pathname1), (void *)pathname);
            events.perf_submit(ctx, &data, sizeof(struct data_t));
        //}
    }

    return 0;
}

int syscall__link(struct pt_regs *ctx, const char __user *pathname1, const char __user *pathname2){
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = task->real_parent->tgid;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int *p;

    p = ppidlist.lookup(&ppid); //PPIDがBPF MAPに存在するか判定

    if(p != 0){//この中に行いたい処理を書く
        if((pathname1[9] == 's') && (pathname2[9] == 's')){
            data.syscallnum = 2;
            data.time = bpf_ktime_get_ns();
            //bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_user(&data.pathname1, sizeof(data.pathname1), (void *)pathname1);
            bpf_probe_read_user(&data.pathname2, sizeof(data.pathname2), (void *)pathname2);
            events.perf_submit(ctx, &data, sizeof(struct data_t));
        }
    }

    return 0;
}

int syscall__unlink(struct pt_regs *ctx, const char __user *pathname){
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = task->real_parent->tgid;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int *p;

    p = ppidlist.lookup(&ppid); //PPIDがBPF MAPに存在するか判定

    if(p != 0){//この中に行いたい処理を書く
        if(pathname[9] == 's'){
            data.syscallnum = 3;
            data.time = bpf_ktime_get_ns();
            //bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_user(&data.pathname1, sizeof(data.pathname1), (void *)pathname);
            events.perf_submit(ctx, &data, sizeof(struct data_t));
        }
    }

    return 0;
}
