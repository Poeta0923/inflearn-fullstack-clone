import { notFound } from "next/navigation";
import UI from "./ui";
import * as api from "@/lib/api";

export default async function EditCourseInfoPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const course = await api.getCourseById(id);
  if (course.error || !course.data) {
    notFound();
  }

  return <UI course={course.data} />;
}
