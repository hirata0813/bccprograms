#include <linux/sched.h>
struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};


// トレースするプロセスを指定するためのハッシュテーブルを定義
// シェルスクリプト内で生成されたプロセス(つまり親プロセスになりうるプロセス)のPIDを保持する
// ppidlist内に格納されているPPIDを持つプロセスのみを監視する
BPF_HASH(ppidlist, int, int);
BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx){
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

int trace_open(struct pt_regs *ctx){
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = task->real_parent->tgid;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int *p;

    p = ppidlist.lookup(&ppid); //PPIDがBPF MAPに存在するか判定

    if(p != 0){//この中に行いたい処理を書く
        data.pid = pid;
        data.ppid = ppid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        events.perf_submit(ctx, &data, sizeof(struct data_t));
    }
    
    return 0;
}
