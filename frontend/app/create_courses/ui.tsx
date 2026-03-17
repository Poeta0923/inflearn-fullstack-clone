"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import * as api from "@/lib/api";
import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

export default function UI() {
  const router = useRouter();
  const [title, setTitle] = useState("");

  const createCourseMutation = useMutation({
    mutationFn: () => api.createCourse(title),
    onSuccess: (res) => {
      if (res.data && !res.error) {
        router.push(`/course/${res.data.id}/edit/course-info`);
      }
      if (res.error) {
        toast.error(res.error as string);
      }
    },
  });

  return (
    <div className="w-full max-w-xl mx-auto h-[70vh] flex flex-col items-center justify-center gap-4 text-center">
      <h1 className="font-bold text-xl">
        제목을 입력해주세요!
        <br />
        너무 고민하지 마세요. 제목은 언제든 수정 가능해요 :)
      </h1>
      <Input
        className="max-w-md bg-gray-100 py-5"
        type="text"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="제목을 입력해주세요!"
      />
      <div className="flex items-center gap-2">
        <Button className="bg-white text-black border shadow-md text-md font-bold px-6 py-5">
          이전
        </Button>
        <Button
          onClick={() => createCourseMutation.mutate()}
          className="bg-green-600 border shadow-md text-md font-bold px-6 py-5"
        >
          만들기
        </Button>
      </div>
    </div>
  );
}
