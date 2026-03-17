"use client";

import { Button } from "@/components/ui/button";
import { X } from "lucide-react";

export default function EditCourseHeader({ title }: { title: string }) {
  return (
    <header className="flex h-16 items-center justify-between bg-white px-6">
      <h2 className="text-lg font-bold">{title}</h2>
      <div className="flex items-center gap-2">
        <Button size="lg">제출</Button>
        <Button variant="outline" size="lg">
          <X size={20} />
        </Button>
      </div>
    </header>
  );
}
