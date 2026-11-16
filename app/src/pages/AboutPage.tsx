import { Cpu, Feather, Layers, ShieldCheck } from "lucide-react";
import appIcon from "../assets/claude-hydra-icon-256.png";
import { Group, Page } from "@/components/PageHeader";
import type { AppInfo } from "@/lib/api";

const points = [
  { icon: Layers, title: "账号互不干扰", text: "每个账号使用独立的数据目录，登录、Cookie 与设置彼此隔离，可以同时打开。" },
  { icon: ShieldCheck, title: "按账号走代理节点", text: "内置本机中继转发到节点，DNS、WebRTC、UDP 不外泄；节点失效时断网而非直连。" },
  { icon: Feather, title: "托盘里几乎不占资源", text: "关闭窗口即销毁界面，仅保留轻量的 Rust 后台进程感知各账号状态。" },
  { icon: Cpu, title: "快捷方式秒开", text: "桌面快捷方式可直接启动或唤醒目标账号。" },
];

export function AboutPage({ info }: { info: AppInfo | null }) {
  return (
    <Page>
      <h1 className="sr-only">关于</h1>
      <div className="space-y-5 px-5 pt-3">
        <div className="flex flex-col items-center py-4 text-center">
          <img src={appIcon} alt="" className="h-16 w-16 rounded-[18px] shadow-card" draggable={false} />
          <div className="mt-3 text-[17px] font-semibold tracking-[-0.01em]">Claude-Hydra</div>
          <div className="mt-0.5 text-[13px] text-muted">同时运行多个 Claude 桌面端账号</div>
          <div className="mt-2.5 inline-flex h-[22px] items-center rounded-full bg-card px-2.5 font-mono text-[11px] text-fg-2 shadow-card">
            {info ? `v${info.version} · ${info.platform}` : "…"}
          </div>
        </div>

        <Group>
          {points.map((p) => (
            <div key={p.title} className="flex items-start gap-3 px-4 py-3">
              <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-pill text-fg-2">
                <p.icon className="h-[15px] w-[15px]" />
              </span>
              <div className="min-w-0">
                <div className="text-[13px] font-medium">{p.title}</div>
                <p className="mt-0.5 text-[12px] leading-[18px] text-muted">{p.text}</p>
              </div>
            </div>
          ))}
        </Group>

      </div>
    </Page>
  );
}
