"use client";

import Link from "next/link";
import { Check } from "lucide-react";
import { useParams, usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export default function EditCourseSidebar() {
  const pathname = usePathname();
  const params = useParams<{ id: string }>();
  const courseId = params.id;

  const sidebarItems = [
    {
      label: "강의 정보",
      href: `/course/${courseId}/edit/course_info`,
    },
    {
      label: "커리큘럼",
      href: `/course/${courseId}/edit/curriculum`,
    },
    {
      label: "상세소개",
      href: `/course/${courseId}/edit/description-builder`,
      description: "200자 이상 작성",
    },
    {
      label: "커버 이미지",
      href: `/course/${courseId}/edit/cover-image`,
    },
  ];

  return (
    <aside className="h-fit w-56 self-start rounded-xl bg-white p-8">
      <h2 className="mb-8 text-lg font-bold text-gray-700">강의 제작</h2>

      <nav className="flex flex-col">
        {sidebarItems.map((item, index) => {
          const isActive = pathname === item.href;
          const isLast = index === sidebarItems.length - 1;

          return (
            <Link
              key={item.href}
              href={item.href}
              className="relative flex gap-4 pb-8"
            >
              {!isLast && (
                <span className="absolute left-[11px] top-6 h-full w-px bg-gray-300" />
              )}

              <span
                className={cn(
                  "z-10 mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-white",
                  isActive
                    ? "border-gray-600 bg-gray-600"
                    : "border-gray-300 bg-gray-300",
                )}
              >
                <Check size={14} />
              </span>

              <span className="flex flex-col">
                <span
                  className={cn(
                    "text-lg leading-none font-semibold",
                    isActive ? "text-gray-700" : "text-gray-400",
                  )}
                >
                  {item.label}
                </span>
                {item.description && (
                  <span className="mt-1 text-sm font-semibold text-gray-400">
                    {item.description}
                  </span>
                )}
              </span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
