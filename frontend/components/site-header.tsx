"use client";

import Image from "next/image";
import Link from "next/link";
import {
  BookOpen,
  Clapperboard,
  Handshake,
  Lightbulb,
  List,
  MessageSquare,
  Search,
  Tag,
  Trophy,
  User,
} from "lucide-react";
import { usePathname } from "next/navigation";

type CategoryLike = {
  id?: number | string;
  name?: string;
  title?: string;
  label?: string;
  slug?: string;
};

type SiteHeaderProps = {
  categories: CategoryLike[];
};

const topTabs = [
  { label: "강의", icon: BookOpen },
  { label: "챌린지", icon: Trophy },
  { label: "멘토링", icon: Handshake },
  { label: "클립", icon: Clapperboard },
  { label: "커뮤니티", icon: MessageSquare },
  { label: "지식공유", icon: Lightbulb, href: "/instructor" },
];
const centerTabs = topTabs.filter((tab) => !tab.href);
const knowledgeShareTab = topTabs.find((tab) => tab.href === "/instructor");

const getCategoryLabel = (category: CategoryLike) => {
  return category.name ?? category.title ?? category.label ?? category.slug ?? "카테고리";
};

const getCategoryKey = (category: CategoryLike, index: number) => {
  return String(category.id ?? category.slug ?? getCategoryLabel(category) ?? index);
};

const getCategoryHref = (category: CategoryLike) => {
  if (!category.slug) {
    return "/courses";
  }

  return `/courses/${encodeURIComponent(category.slug)}`;
};

export default function SiteHeader({ categories }: SiteHeaderProps) {
  const pathname = usePathname();
  const isCourseRoute =
    pathname === "/courses" || pathname.startsWith("/courses/");
  const isCategoryNeeded = pathname === "/" || isCourseRoute;
  const isAllActive = pathname === "/";

  return (
    <header className="border-b border-gray-200 bg-white">
      <div className="mx-auto grid h-16 w-full max-w-7xl grid-cols-[auto_1fr_auto] items-center px-4">
        <div className="flex items-center">
          <Link href="/" aria-label="Inflearn 홈">
            <Image
              src="/inflearn_logo_default.svg"
              alt="Inflearn"
              width={110}
              height={45}
              priority
              className="h-9 w-auto"
            />
          </Link>
        </div>

        <nav className="flex items-center justify-center gap-5">
          {centerTabs.map(({ label, icon: Icon }) => (
            <button
              key={label}
              type="button"
              className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 transition-colors hover:text-emerald-500"
            >
              <Icon size={16} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-3 justify-self-end">
          {knowledgeShareTab && (
            <Link
              href={knowledgeShareTab.href ?? "/instructor"}
              className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 transition-colors hover:text-emerald-500"
            >
              <knowledgeShareTab.icon size={16} />
              <span>{knowledgeShareTab.label}</span>
            </Link>
          )}

          <button
            type="button"
            aria-label="프로필"
            className="flex h-8 w-8 items-center justify-center rounded-full border border-gray-200 bg-gray-50 text-gray-500 transition-colors hover:text-emerald-500"
          >
            <User size={16} />
          </button>
        </div>
      </div>

      <div>
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center px-4">
          <div className="mx-auto flex h-11 w-full max-w-2xl items-center rounded-full border border-gray-200 px-4 shadow-sm">
            <button
              type="button"
              aria-label="검색"
              className="text-gray-400 transition-colors hover:text-emerald-500"
            >
              <Search size={18} />
            </button>
            <input
              type="text"
              placeholder="우리는 성장 기회의 평등을 추구합니다."
              className="w-full bg-transparent px-3 text-sm text-gray-700 placeholder:text-gray-400 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {isCategoryNeeded && (
        <div className="mx-auto flex h-14 w-full max-w-7xl items-center gap-6 overflow-x-auto px-4">
          <Link
            href="/"
            className={`flex shrink-0 items-center gap-1.5 pb-1 text-sm transition-colors ${
              isAllActive
                ? "border-b-2 border-emerald-500 font-semibold text-gray-900"
                : "text-gray-700 hover:text-emerald-500"
            }`}
          >
            <List size={16} />
            <span>전체</span>
          </Link>

          {categories.map((category, index) => {
            const categoryHref = getCategoryHref(category);
            const isCategoryActive = pathname === categoryHref;

            return (
              <Link
                key={getCategoryKey(category, index)}
                href={categoryHref}
                className={`flex shrink-0 items-center gap-1.5 pb-1 text-sm transition-colors ${
                  isCategoryActive
                    ? "border-b-2 border-emerald-500 font-semibold text-gray-900"
                    : "text-gray-700 hover:text-emerald-500"
                }`}
              >
                <Tag size={16} />
                <span>{getCategoryLabel(category)}</span>
              </Link>
            );
          })}
        </div>
      )}
    </header>
  );
}
