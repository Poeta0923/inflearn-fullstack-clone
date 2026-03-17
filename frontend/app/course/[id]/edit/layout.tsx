import { notFound } from "next/navigation";
import EditCourseHeader from "./_components/edit-course-header";
import EditCourseSidebar from "./_components/edit-course-sidebar";
import * as api from "@/lib/api";

export default async function EditCourseLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const course = await api.getCourseById(id);

  if (course.error || !course.data) {
    notFound();
  }

  return (
    <div className="min-h-screen w-full bg-gray-200">
      <EditCourseHeader title={course.data?.title} />
      <div className="mx-auto flex w-full max-w-7xl gap-6 p-6">
        <EditCourseSidebar />
        <main className="min-h-[500px] flex-1 rounded-xl bg-white p-6">{children}</main>
      </div>
    </div>
  );
}