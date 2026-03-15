import * as api from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import CourseManagementActions from "@/app/instructor/courses/course-management-actions";

const KRW_FORMATTER = new Intl.NumberFormat("ko-KR");

const formatCurrency = (price: number) => `${KRW_FORMATTER.format(price)}원`;

export default async function InstructorCoursesPage() {
  const instructorCourses = await api.getAllInstructorCourses();
  const courses = instructorCourses.data ?? [];

  return (
    <div className="mx-auto w-full max-w-7xl p-6">
      <h1 className="mb-4 text-2xl font-bold">강의 관리</h1>

      {Boolean(instructorCourses.error) && (
        <p className="mb-4 text-sm text-red-600">
          강의 정보를 불러오는 중 오류가 발생했습니다.
        </p>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>이미지</TableHead>
            <TableHead>강의명</TableHead>
            <TableHead>평점</TableHead>
            <TableHead>총 수강생</TableHead>
            <TableHead>질문</TableHead>
            <TableHead>가격(할인가)</TableHead>
            <TableHead>총 수입</TableHead>
            <TableHead>상태</TableHead>
            <TableHead>관리</TableHead>
          </TableRow>
        </TableHeader>

        <TableBody>
          {courses.length === 0 && (
            <TableRow>
              <TableCell colSpan={9} className="py-8 text-center text-gray-500">
                등록된 강의가 없습니다.
              </TableCell>
            </TableRow>
          )}

          {courses.map((course) => {
            const averageRating = 0;
            const studentsCount = 0;
            const questionCount = 0;
            const totalRevenue = 0;
            const isPublishedStatus = course.status === "PUBLISHED";
            const statusLabel =
              course.status === "DRAFT"
                ? "임시저장"
                : course.status === "PUBLISHED"
                  ? "게시중"
                  : course.status;

            return (
              <TableRow key={course.id}>
                <TableCell>
                  <div className="h-12 w-20 overflow-hidden rounded-md border border-gray-200 bg-gray-100">
                    {course.thumbnailUrl ? (
                      <img
                        src={course.thumbnailUrl}
                        alt={`${course.title} 썸네일`}
                        className="h-full w-full object-cover"
                      />
                    ) : (
                      <div className="flex h-full w-full items-center justify-center text-xs text-gray-400">
                        이미지 없음
                      </div>
                    )}
                  </div>
                </TableCell>

                <TableCell className="font-medium">{course.title}</TableCell>
                <TableCell>{averageRating.toFixed(1)}</TableCell>
                <TableCell>{studentsCount}명</TableCell>
                <TableCell>{questionCount}개</TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <span>{formatCurrency(course.price)}</span>
                    {course.discountPrice !== undefined && (
                      <span className="text-emerald-600">
                        ({formatCurrency(course.discountPrice)})
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell>{formatCurrency(totalRevenue)}</TableCell>
                <TableCell>
                  <Badge
                    variant={isPublishedStatus ? "default" : "secondary"}
                    className="rounded-md"
                  >
                    {statusLabel}
                  </Badge>
                </TableCell>
                <TableCell>
                  <CourseManagementActions courseId={course.id} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}