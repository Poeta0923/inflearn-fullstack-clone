"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { cn } from "@/lib/utils";

const sidebarItems = [
  {
    label: "대시보드",
    href: "/instructor",
  },
  {
    label: "새 강의 만들기",
    href: "/create_courses",
  },
  {
    label: "강의 관리",
    href: "/instructor/courses",
  },
  {
    label: "미션 관리",
    href: "/instructor#",
  },
  {
    label: "멘토링 관리",
    href: "/instructor#",
  },
  {
    label: "강의 질문 관리",
    href: "/instructor#",
  },
  {
    label: "수강평 리스트",
    href: "/instructor#",
  },
  {
    label: "새소식 관리",
    href: "/instructor#",
  },
  {
    label: "수익 확인",
    href: "/instructor#",
  },
  {
    label: "쿠폰 관리",
    href: "/instructor#",
  },
  {
    label: "수강전 문의 관리",
    href: "/instructor#",
  },
  {
    label: "로드맵 관리",
    href: "/instructor#",
  },
  {
    label: "지식공유자 가이드",
    href: "/instructor#",
  },
];

export default function InstructorSidebar() {
  const pathname = usePathname();
  const [selectedTab, setSelectedTab] = useState("");

  const alertPreparing = (label: string) => {
    setSelectedTab(label);
    alert("준비중입니다.");
  };

  return (
    <aside className="w-64 shrink-0 border-r border-gray-200 bg-white">
      <nav className="flex flex-col gap-1 p-4">
        {sidebarItems.map((item) => {
          const isPreparingItem = item.href.endsWith("#");
          const isActive = isPreparingItem
            ? selectedTab === item.label
            : pathname === item.href;

          if (isPreparingItem) {
            return (
              <button
                key={`${item.label}-${item.href}`}
                type="button"
                onClick={() => alertPreparing(item.label)}
                className={cn(
                  "w-full rounded-md px-3 py-2 text-left text-sm font-medium transition-colors",
                  isActive
                    ? "bg-emerald-50 text-emerald-700"
                    : "text-gray-700 hover:bg-gray-100 hover:text-gray-900",
                )}
              >
                {item.label}
              </button>
            );
          }

          return (
            <Link
              key={`${item.label}-${item.href}`}
              href={item.href}
              onClick={() => setSelectedTab("")}
              className={cn(
                "rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-emerald-50 text-emerald-700"
                  : "text-gray-700 hover:bg-gray-100 hover:text-gray-900",
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
