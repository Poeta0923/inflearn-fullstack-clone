"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";

type CourseManagementActionsProps = {
  courseId: string;
};

export default function CourseManagementActions({
  courseId,
}: CourseManagementActionsProps) {
  const router = useRouter();

  const handleEditCourse = () => {
    router.push(`/course/${courseId}/edit/course_info`);
  };

  const handleDeleteCourse = () => {
    window.confirm("정말 삭제하시겠습니까?");
  };

  return (
    <div className="flex flex-col items-start gap-2">
      <Button size="sm" variant="outline" onClick={handleEditCourse}>
        강의 수정
      </Button>
      <Button size="sm" variant="destructive" onClick={handleDeleteCourse}>
        강의 삭제
      </Button>
    </div>
  );
}
