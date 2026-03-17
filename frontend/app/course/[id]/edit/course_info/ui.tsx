"use client";

import { useForm } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Course } from "@/generated/openapi-client";
import { useMutation } from "@tanstack/react-query";
import * as api from "@/lib/api";
import { toast } from "sonner";

type CourseInfoFormValues = {
  title: string;
  shortDescription: string;
  price: number;
  discountPrice: number;
  level: "BEGINNER" | "INTERMEDIATE" | "ADVANCED";
  status: "PUBLISHED" | "DRAFT";
};

export default function EditCourseInfoUI({ course }: { course: Course }) {
  const form = useForm<CourseInfoFormValues>({
    defaultValues: {
      title: course.title,
      shortDescription: course.shortDescription ?? "",
      price: course.price ?? 0,
      discountPrice: course.discountPrice ?? 0,
      level:
        (course.level as "BEGINNER" | "INTERMEDIATE" | "ADVANCED") ??
        "BEGINNER",
      status: (course.status as "PUBLISHED" | "DRAFT") ?? "DRAFT",
    },
  });

  const updateCourseMutation = useMutation({
    mutationFn: (data: CourseInfoFormValues) =>
      api.updateCourse(course.id, data),
    onSuccess: () => {
      toast.success("강의 정보가 성공적으로 업데이트되었습니다.");
    },
  });

  const onSubmit = (data: CourseInfoFormValues) => {
    updateCourseMutation.mutate(data);
  };

  return (
    <div className="mx-auto w-full max-w-4xl rounded-xl bg-white p-8">
      <p className="mb-1 text-sm font-semibold text-gray-500">강의 제작</p>
      <h2 className="mb-8 text-4xl font-bold text-gray-800">강의 정보</h2>

      <div className="mb-6 text-right text-sm text-gray-600">
        <span className="mr-1 text-red-500">*</span>
        필수 입력 항목입니다.
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
          <FormField
            control={form.control}
            name="title"
            rules={{ required: "강의 제목은 필수입니다." }}
            render={({ field }) => (
              <FormItem>
                <FormLabel className="text-xl font-bold text-gray-700">
                  강의 제목 <span className="text-red-500">*</span>
                </FormLabel>
                <FormControl>
                  <Input placeholder="제목을 입력해주세요." {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="shortDescription"
            rules={{ required: "강의 두줄 요약은 필수입니다." }}
            render={({ field }) => (
              <FormItem>
                <FormLabel className="text-xl font-bold text-gray-700">
                  강의 두줄 요약 <span className="text-red-500">*</span>
                </FormLabel>
                <FormDescription className="text-sm text-red-400">
                  강의소개 상단에 보여집니다. 잠재 수강생들이 매력을 느낄만한
                  글을 짧게 남겨주세요.
                </FormDescription>
                <FormControl>
                  <Textarea
                    placeholder="예) 이 강의를 통해 수강생은 ..."
                    className="min-h-9"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid grid-cols-1 gap-6">
            <FormField
              control={form.control}
              name="price"
              rules={{ required: "강의 가격은 필수입니다." }}
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-lg font-bold text-gray-700">
                    강의 가격 <span className="text-red-500">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={0}
                      value={field.value}
                      onChange={(e) => field.onChange(Number(e.target.value))}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="discountPrice"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-lg font-bold text-gray-700">
                    강의 할인 가격
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={0}
                      value={field.value}
                      onChange={(e) => field.onChange(Number(e.target.value))}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <div className="grid grid-cols-1 gap-6">
            <FormField
              control={form.control}
              name="level"
              rules={{ required: "난이도를 선택해주세요." }}
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-lg font-bold text-gray-700">
                    난이도 <span className="text-red-500">*</span>
                  </FormLabel>
                  <Select
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                  >
                    <FormControl>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="난이도를 선택해주세요." />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="BEGINNER">입문</SelectItem>
                      <SelectItem value="INTERMEDIATE">초급</SelectItem>
                      <SelectItem value="ADVANCED">중급</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="status"
              rules={{ required: "상태를 선택해주세요." }}
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-lg font-bold text-gray-700">
                    상태 <span className="text-red-500">*</span>
                  </FormLabel>
                  <Select
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                  >
                    <FormControl>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="상태를 선택해주세요." />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="PUBLISHED">PUBLISHED</SelectItem>
                      <SelectItem value="DRAFT">DRAFT</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <div className="flex justify-end">
            <Button
              type="submit"
              className="bg-emerald-500 hover:bg-emerald-600"
            >
              저장하기
            </Button>
          </div>
        </form>
      </Form>
    </div>
  );
}
